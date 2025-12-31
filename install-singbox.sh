#!/usr/bin/env bash
set -euo pipefail

# ==========================================
# 基础变量声明与环境准备
# ==========================================
SBOX_ARCH=""
OS_DISPLAY=""
SBOX_CORE="/etc/sing-box/core_script.sh"

# 优化变量容器 (由 optimize_system 计算并填充)
SBOX_GOLIMIT="52MiB"
SBOX_GOGC="80"
SBOX_MEM_MAX="55M"
SBOX_MEM_HIGH=""
SBOX_GOMAXPROCS=""
SBOX_OPTIMIZE_LEVEL="未检测"
VAR_UDP_RMEM=""
VAR_UDP_WMEM=""
VAR_SYSTEMD_NICE=""
VAR_SYSTEMD_IOSCHED=""
# 新增：带宽推荐值
SBOX_MAX_BW_UP=0
SBOX_MAX_BW_DOWN=0

# TLS 域名随机池 (针对中国大陆环境优化)
TLS_DOMAIN_POOL=(
  "www.bing.com"                # 推荐：全球 IP 分布，合法性高
  "www.microsoft.com"           # 推荐：系统更新流量，极具迷惑性
  "download.windowsupdate.com"  # 推荐：大流量 UDP 伪装的首选
  "www.icloud.com"              # 推荐：苹果用户常态化出境流量
  "gateway.icloud.com"          # 推荐：iCloud 同步流量
  "cdn.staticfile.org"          # 推荐：国内知名的开源库加速，常去境外取回数据
)
pick_tls_domain() { echo "${TLS_DOMAIN_POOL[$RANDOM % ${#TLS_DOMAIN_POOL[@]}]}"; }
TLS_DOMAIN="$(pick_tls_domain)"

# ==========================================
# 彩色输出与工具函数
# ==========================================
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }
succ() { echo -e "\033[1;32m[OK]\033[0m $*"; }

# OSC 52 自动复制到剪贴板函数
copy_to_clipboard() {
    local content="$1"
    if [ -n "${SSH_TTY:-}" ] || [ -n "${DISPLAY:-}" ]; then
        local b64_content=$(printf "%b" "$content" | base64 | tr -d '\r\n')
        echo -ne "\033]52;c;${b64_content}\a"
        echo -e "\033[1;32m[复制]\033[0m 节点链接已推送至本地剪贴板"
    fi
}

# 检测系统与架构
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

    if echo "${ID:-} ${ID_LIKE:-}" | grep -qi "alpine"; then
        OS="alpine"
    elif echo "${ID:-} ${ID_LIKE:-}" | grep -Ei "debian|ubuntu" >/dev/null; then
        OS="debian"
    elif echo "${ID:-} ${ID_LIKE:-}" | grep -Ei "centos|rhel|fedora|rocky|almalinux" >/dev/null; then
        OS="redhat"
    else
        OS="unknown"
    fi

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)    SBOX_ARCH="amd64" ;;
        aarch64)   SBOX_ARCH="arm64" ;;
        armv7l)    SBOX_ARCH="armv7" ;;
        i386|i686) SBOX_ARCH="386" ;;
        *) err "不支持的架构: $ARCH"; exit 1 ;;
    esac
}

# 依赖安装
install_dependencies() {
    info "正在检查并安装必要依赖 (curl, jq, openssl, iperf3)..."
    case "$OS" in
        alpine)
            apk add --no-cache bash curl jq openssl openrc iproute2 coreutils grep iperf3 ethtool
            ;;
        debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y || true
            apt-get install -y curl jq openssl coreutils grep iperf3 ethtool
            ;;
        redhat)
            yum install -y curl jq openssl coreutils grep iperf3 ethtool
            ;;
        *)
            err "不支持的系统发行版: $OS"; exit 1 ;;
    esac
}

get_network_info() {
    info "正在获取网络地址..."
    RAW_IP4=$(curl -s4 --max-time 5 https://api.ipify.org || curl -s4 --max-time 5 https://ifconfig.me || echo "")
    RAW_IP6=$(curl -s6 --max-time 5 https://api6.ipify.org || curl -s6 --max-time 5 https://ifconfig.co || echo "")
    [ -n "$RAW_IP4" ] && echo -e "IPv4 地址: \033[32m$RAW_IP4\033[0m" || echo -e "IPv4 地址: \033[33m未检测到\033[0m"
    [ -n "$RAW_IP6" ] && echo -e "IPv6 地址: \033[32m$RAW_IP6\033[0m" || echo -e "IPv6 地址: \033[33m未检测到\033[0m"
}

# ==========================================
# 带宽实测模块 (iperf3 模式)
# ==========================================
test_bandwidth() {
    info "正在执行回国带宽实测 (由 iperf3 驱动, 耗时约 10s)..."
    # 使用国内公共 iperf3 服务器 (如果不可用则跳过)
    # 逻辑：实测带宽 Mbps * 0.85 作为建议值
    local test_res=$(iperf3 -c 1.12.35.49 -p 5201 -R -t 5 --json 2>/dev/null || iperf3 -c fs.fastvps.ru -p 5201 -R -t 5 --json 2>/dev/null || echo "fail")
    
    if [[ "$test_res" != "fail" ]]; then
        local bw_bps=$(echo "$test_res" | jq '.end.sum_received.bits_per_second // 0')
        local bw_mbps=$(echo "scale=0; $bw_bps / 1000000" | bc 2>/dev/null || echo "0")
        if [ "$bw_mbps" -gt 0 ]; then
            # 85% 经验准则
            SBOX_MAX_BW_DOWN=$((bw_mbps * 85 / 100))
            SBOX_MAX_BW_UP=$((SBOX_MAX_BW_DOWN / 3)) # 假设上行是下行的 1/3
            succ "带宽测速完成：下行约 ${bw_mbps}Mbps，建议设置：${SBOX_MAX_BW_DOWN}Mbps"
            return
        fi
    fi
    warn "测速失败或服务器不可达，将不启用带宽硬限制限制"
}

# ==========================================
# 系统内核优化 (核心逻辑：差异化 + 进程调度 + UDP极限)
# ==========================================
optimize_system() {
    # 0. RTT 感知模块
    local RTT_AVG
    set +e 
    RTT_AVG=$(ping -c 2 -W 1 223.5.5.5 2>/dev/null | awk -F'/' 'END{print int($5)}')
    if [ -z "$RTT_AVG" ] || [ "$RTT_AVG" -eq 0 ]; then
        RTT_AVG=$(ping -c 2 -W 1 1.1.1.1 2>/dev/null | awk -F'/' 'END{print int($5)}')
    fi
    set -e

    if [ -n "${RTT_AVG:-}" ] && [ "$RTT_AVG" -gt 0 ]; then
        info "实时网络探测完成，当前平均 RTT: ${RTT_AVG}ms"
    else
        # 智能地理位置补偿
        if [ -z "${RAW_IP4:-}" ]; then
            RTT_AVG=150
        else
            info "Ping 探测受阻，正在通过 IP-API 预估 RTT..."
            local LOC=$(curl -s --max-time 3 "http://ip-api.com/line/${RAW_IP4}?fields=country" || echo "Unknown")
            case "$LOC" in
                "China"|"Hong Kong"|"Japan"|"Korea"|"Singapore"|"Taiwan") RTT_AVG=50 ;;
                "Germany"|"France"|"United Kingdom"|"Netherlands"|"Spain"|"Poland"|"Italy") RTT_AVG=180 ;;
                "United States"|"Canada"|"Mexico") RTT_AVG=220 ;;
                *) RTT_AVG=150 ;;
            esac
        fi
    fi

    # 1. 内存检测
    local mem_total=64
    local mem_cgroup=0
    local mem_host_total=$(free -m | awk '/Mem:/ {print $2}')

    if [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        mem_cgroup=$(($(cat /sys/fs/cgroup/memory/memory.limit_in_bytes) / 1024 / 1024))
    elif [ -f /sys/fs/cgroup/memory.max ]; then
        local m_max=$(cat /sys/fs/cgroup/memory.max)
        [[ "$m_max" =~ ^[0-9]+$ ]] && mem_cgroup=$((m_max / 1024 / 1024))
    elif grep -q "MemTotal" /proc/meminfo; then
        mem_cgroup=$(($(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024))
    fi

    if [ "$mem_cgroup" -gt 0 ] && [ "$mem_cgroup" -le "$mem_host_total" ]; then
        mem_total=$mem_cgroup
    else
        mem_total=$mem_host_total
    fi
    if [ -f /proc/user_beancounters ]; then mem_total=$mem_host_total; SBOX_OPTIMIZE_LEVEL="OpenVZ容器版"; fi
    if [ "$mem_total" -le 0 ] || [ "$mem_total" -gt 64000 ]; then mem_total=64; fi

    info "系统画像: 可用内存=${mem_total}MB | 平均延迟=${RTT_AVG}ms"

    # 2. 差异化档位与你提供的 QUIC 专用调度合并
    local udp_mem_scale
    local max_udp_mb=$((mem_total * 40 / 100)) 
    local max_udp_pages=$((max_udp_mb * 256)) 

    # QUIC 专用自适应模板
    local QUIC_UDP_MEM_MIN QUIC_UDP_MEM_PRESS QUIC_UDP_MEM_MAX QUIC_UDP_RMEM_MIN QUIC_UDP_WMEM_MIN QUIC_OPT_LEVEL
    if [ "$RTT_AVG" -ge 150 ]; then
        QUIC_UDP_MEM_MIN=262144; QUIC_UDP_MEM_PRESS=524288; QUIC_UDP_MEM_MAX=1048576
        QUIC_UDP_RMEM_MIN=32768; QUIC_UDP_WMEM_MIN=32768; QUIC_OPT_LEVEL="QUIC 国际模式"
    else
        QUIC_UDP_MEM_MIN=131072; QUIC_UDP_MEM_PRESS=262144; QUIC_UDP_MEM_MAX=524288
        QUIC_UDP_RMEM_MIN=16384; QUIC_UDP_WMEM_MIN=16384; QUIC_OPT_LEVEL="QUIC 亚洲模式"
    fi

    # 基础内存档位
    if [ "$mem_total" -ge 450 ]; then
        SBOX_GOLIMIT="420MiB"; SBOX_GOGC="120"; VAR_UDP_RMEM="67108864"; VAR_UDP_WMEM="67108864"
        VAR_SYSTEMD_NICE="-15"; VAR_SYSTEMD_IOSCHED="realtime"; SBOX_OPTIMIZE_LEVEL="512M 旗舰版"
    elif [ "$mem_total" -ge 200 ]; then
        SBOX_GOLIMIT="210MiB"; SBOX_GOGC="100"; VAR_UDP_RMEM="33554432"; VAR_UDP_WMEM="33554432"
        VAR_SYSTEMD_NICE="-10"; VAR_SYSTEMD_IOSCHED="best-effort"; SBOX_OPTIMIZE_LEVEL="256M 增强版"
    elif [ "$mem_total" -ge 100 ]; then
        SBOX_GOLIMIT="100MiB"; SBOX_GOGC="70"; VAR_UDP_RMEM="16777216"; VAR_UDP_WMEM="16777216"
        VAR_SYSTEMD_NICE="-5"; VAR_SYSTEMD_IOSCHED="best-effort"; SBOX_OPTIMIZE_LEVEL="128M 紧凑版"
    else
        SBOX_GOLIMIT="52MiB"; SBOX_GOGC="50"; VAR_UDP_RMEM="8388608"; VAR_UDP_WMEM="8388608"
        VAR_SYSTEMD_NICE="-2"; VAR_SYSTEMD_IOSCHED="best-effort"; SBOX_GOMAXPROCS="1"; SBOX_OPTIMIZE_LEVEL="64M 生存版"
    fi

    # 合并 udp_mem (取最大值)
    local base_rtt_min=$((RTT_AVG * 128))
    local base_rtt_press=$((RTT_AVG * 256))
    local base_rtt_max=$((RTT_AVG * 512))
    
    local final_u_min=$( [ $base_rtt_min -gt $QUIC_UDP_MEM_MIN ] && echo $base_rtt_min || echo $QUIC_UDP_MEM_MIN )
    local final_u_press=$( [ $base_rtt_press -gt $QUIC_UDP_MEM_PRESS ] && echo $base_rtt_press || echo $QUIC_UDP_MEM_PRESS )
    local final_u_max=$( [ $base_rtt_max -gt $QUIC_UDP_MEM_MAX ] && echo $base_rtt_max || echo $QUIC_UDP_MEM_MAX )

    # 安全钳位
    [ "$final_u_max" -gt "$max_udp_pages" ] && final_u_max=$max_udp_pages
    udp_mem_scale="$final_u_min $final_u_press $final_u_max"
    SBOX_MEM_MAX="$((mem_total * 92 / 100))M"
    SBOX_MEM_HIGH="$((mem_total * 80 / 100))M"
    SBOX_OPTIMIZE_LEVEL="$SBOX_OPTIMIZE_LEVEL + $QUIC_OPT_LEVEL"

    # 3. Swap 兜底
    if [ "$OS" != "alpine" ]; then
        local swap_total=$(free -m | awk '/Swap:/ {print $2}')
        if [ "$swap_total" -lt 10 ] && [ "$mem_total" -lt 150 ]; then
            warn "检测到内存吃紧，正在创建 128MB 应急 Swap..."
            fallocate -l 128M /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=128 2>/dev/null
            chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
            grep -q "/swapfile" /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab
        fi
    fi

    # 4. 内核写入 (优化整合)
    local tcp_cca="bbr"
    modprobe tcp_bbr >/dev/null 2>&1 || true
    if sysctl net.ipv4.tcp_available_congestion_control | grep -q "bbr"; then tcp_cca="bbr"; fi

    # 使用 .d 目录防止覆盖原有配置
    mkdir -p /etc/sysctl.d/
    cat > /etc/sysctl.d/99-singbox.conf <<SYSCTL
# === 基础网络与拥塞控制 ===
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = $tcp_cca
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_fastopen = 3

# === QUIC 专用调度与 Busy Poll ===
net.core.busy_read = 50
net.core.busy_poll = 50
net.core.optmem_max = 1048576
net.ipv4.tcp_limit_output_bytes = 262144
net.core.netdev_budget_usecs = 8000

# === UDP 极限优化 ===
net.core.rmem_max = $VAR_UDP_RMEM
net.core.wmem_max = $VAR_UDP_WMEM
net.core.rmem_default = 2097152
net.core.wmem_default = 2097152
net.ipv4.udp_mem = $udp_mem_scale
net.ipv4.udp_rmem_min = $QUIC_UDP_RMEM_MIN
net.ipv4.udp_wmem_min = $QUIC_UDP_WMEM_MIN

# === 路由与队列 ===
net.core.netdev_max_backlog = 30000
net.core.somaxconn = 16384
net.ipv4.ip_forward = 1
vm.swappiness = 10
SYSCTL
    sysctl -p /etc/sysctl.d/99-singbox.conf >/dev/null 2>&1 || true

    # 5. NIC 卸载优化 (关键：防止 HY2 速率抖动)
    if command -v ethtool >/dev/null 2>&1; then
        local IFACE=$(ip route show default | awk '{print $5; exit}')
        [ -n "$IFACE" ] && {
            # 开启 GRO/GSO，关闭 TSO/LRO 防止 UDP 包合并乱序
            ethtool -K "$IFACE" gro on gso on tso off lro off >/dev/null 2>&1 || true
        }
    fi

    # 6. 强力 InitCWND 注入 (适配虚化小鸡)
    if command -v ip >/dev/null; then
        local default_info=$(ip route show default | head -n1)
        local gateway=$(echo $default_info | awk '{print $3}')
        local dev=$(echo $default_info | awk '{print $5}')
        local src=$(ip -4 addr show $dev | grep inet | awk '{print $2}' | cut -d/ -f1 | head -n1)
        # 使用 replace 强制覆盖，并补全 src 防止路由选择失败
        if [ -n "$gateway" ] && [ -n "$dev" ]; then
            ip route replace default via $gateway dev $dev src $src initcwnd 15 initrwnd 15 2>/dev/null || true
            succ "InitCWND 强行注入成功 (15)"
        fi
    fi
}

# ==========================================
# 安装/更新 Sing-box 内核
# ==========================================
install_singbox() {
    local MODE="${1:-install}"
    local LOCAL_VER="未安装"
    [ -f /usr/bin/sing-box ] && LOCAL_VER=$(/usr/bin/sing-box version | head -n1 | awk '{print $3}')

    info "正在连接 GitHub API 获取版本信息..."
    local RELEASE_JSON=$(curl -sL --max-time 15 https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null)
    local LATEST_TAG=$(echo "$RELEASE_JSON" | jq -r .tag_name 2>/dev/null || echo "null")
    local DOWNLOAD_SOURCE="GitHub"

    if [ "$LATEST_TAG" = "null" ] || [ -z "$LATEST_TAG" ]; then
        LATEST_TAG=$(curl -sL --max-time 10 https://sing-box.org/ | grep -oE 'v1\.[0-9]+\.[0-9]+' | head -n1 || echo "")
        DOWNLOAD_SOURCE="官方镜像"
    fi

    if [ -z "$LATEST_TAG" ]; then
        if [ "$LOCAL_VER" != "未安装" ]; then return 0; else err "获取版本失败"; exit 1; fi
    fi

    local REMOTE_VER="${LATEST_TAG#v}"
    if [[ "$MODE" == "update" ]]; then
        if [[ "$LOCAL_VER" == "$REMOTE_VER" ]]; then succ "内核已是最新"; return 1; fi
    fi

    local URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST_TAG}/sing-box-${REMOTE_VER}-linux-${SBOX_ARCH}.tar.gz"
    local TMP_D=$(mktemp -d)
    if ! curl -fL --max-time 30 "$URL" -o "$TMP_D/sb.tar.gz"; then
        URL="https://mirror.ghproxy.com/${URL}"
        curl -fL --max-time 30 "$URL" -o "$TMP_D/sb.tar.gz"
    fi

    if [ -f "$TMP_D/sb.tar.gz" ]; then
        tar -xf "$TMP_D/sb.tar.gz" -C "$TMP_D"
        pgrep sing-box >/dev/null && (systemctl stop sing-box 2>/dev/null || rc-service sing-box stop 2>/dev/null || true)
        install -m 755 "$TMP_D"/sing-box-*/sing-box /usr/bin/sing-box
        rm -rf "$TMP_D"
        succ "内核安装成功: v$(/usr/bin/sing-box version | head -n1 | awk '{print $3}')"
        return 0
    fi
}

# ==========================================
# 端口与证书工具
# ==========================================
is_valid_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1025 ] && [ "$port" -le 65535 ]; then return 0; else return 1; fi
}

prompt_for_port() {
    local input_port
    while true; do
        read -p "请输入端口 [1025-65535] (回车随机生成): " input_port
        if [[ -z "$input_port" ]]; then
            input_port=$(shuf -i 10000-60000 -n 1)
            echo "$input_port" && return 0
        elif is_valid_port "$input_port"; then
            echo "$input_port" && return 0
        fi
    done
}

generate_cert() {
    info "生成 ECC P-256 高性能证书 (伪装: $TLS_DOMAIN)..."
    mkdir -p /etc/sing-box/certs
    if [ ! -f /etc/sing-box/certs/fullchain.pem ]; then
        openssl ecparam -genkey -name prime256v1 -out /etc/sing-box/certs/privkey.pem
        openssl req -new -x509 -days 3650 \
          -key /etc/sing-box/certs/privkey.pem \
          -out /etc/sing-box/certs/fullchain.pem \
          -subj "/CN=$TLS_DOMAIN"
    fi
}

# ==========================================
# 配置文件生成 (整合带宽限制)
# ==========================================
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
    
    # 构造带宽限制配置 (若测速成功则应用)
    local bw_config=""
    if [ "$SBOX_MAX_BW_UP" -gt 0 ]; then
        bw_config=", \"up\": \"$SBOX_MAX_BW_UP Mbps\", \"down\": \"$SBOX_MAX_BW_DOWN Mbps\""
    fi

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
    "udp_timeout": "5m",
    "udp_fragment": true$bw_config,
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

# ==========================================
# 服务配置 (整合 GODEBUG 增强)
# ==========================================
setup_service() {
    info "配置系统服务 (MEM限制: $SBOX_MEM_MAX)..."
    
    local env_list=(
        "Environment=GOGC=${SBOX_GOGC:-80}"
        "Environment=GOMEMLIMIT=$SBOX_GOLIMIT"
        "Environment=GODEBUG=madvdontneed=1,memprofilerate=0"
        "Environment=GOTRACEBACK=none"
    )
    [ -n "${SBOX_GOMAXPROCS:-}" ] && env_list+=("Environment=GOMAXPROCS=$SBOX_GOMAXPROCS")

    if [ "$OS" = "alpine" ]; then
        local openrc_exports=$(printf "export %s\n" "${env_list[@]}" | sed 's/Environment=//g')
        cat > /etc/init.d/sing-box <<EOF
#!/sbin/openrc-run
name="sing-box"
$openrc_exports
command="/usr/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
pidfile="/run/\${RC_SVCNAME}.pid"
EOF
        chmod +x /etc/init.d/sing-box
        rc-update add sing-box default && rc-service sing-box restart
    else
        local systemd_envs=$(printf "%s\n" "${env_list[@]}")
        cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-box Service (Optimized)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/sing-box
$systemd_envs
Nice=${VAR_SYSTEMD_NICE}
IOSchedulingClass=${VAR_SYSTEMD_IOSCHED}
IOSchedulingPriority=0
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
MemoryHigh=${SBOX_MEM_HIGH:-}
MemoryMax=$SBOX_MEM_MAX
LimitNOFILE=1000000
LimitNPROC=infinity

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload && systemctl enable sing-box --now
    fi
}

# ==========================================
# 信息展示模块
# ==========================================
get_env_data() {
    local CONFIG_FILE="/etc/sing-box/config.json"
    [ ! -f "$CONFIG_FILE" ] && return 1
    RAW_PSK=$(jq -r '.inbounds[0].users[0].password' "$CONFIG_FILE" | xargs)
    RAW_PORT=$(jq -r '.inbounds[0].listen_port' "$CONFIG_FILE" | xargs)
    local CERT_PATH=$(jq -r '.inbounds[0].tls.certificate_path' "$CONFIG_FILE" | xargs)
    RAW_SNI=$(openssl x509 -in "$CERT_PATH" -noout -subject -nameopt RFC2253 | sed 's/.*CN=\([^,]*\).*/\1/' | xargs)
}

display_links() {
    local LINK_V4="" LINK_V6="" FULL_CLIP=""
    if [ -z "${RAW_IP4:-}" ] && [ -z "${RAW_IP6:-}" ]; then return; fi

    echo -e "\n\033[1;32m[节点信息]\033[0m \033[1;34m>>>\033[0m 运行端口: \033[1;33m${RAW_PORT}\033[0m"
    [ -n "${RAW_IP4:-}" ] && {
        LINK_V4="hy2://$RAW_PSK@$RAW_IP4:$RAW_PORT/?sni=$RAW_SNI&alpn=h3&insecure=1#$(hostname)_v4"
        FULL_CLIP="$LINK_V4"
        echo -e "\n\033[1;35m[IPv4节点链接]\033[0m\n$LINK_V4\n"
    }
    [ -n "${RAW_IP6:-}" ] && {
        LINK_V6="hy2://$RAW_PSK@[$RAW_IP6]:$RAW_PORT/?sni=$RAW_SNI&alpn=h3&insecure=1#$(hostname)_v6"
        [ -n "$FULL_CLIP" ] && FULL_CLIP="${FULL_CLIP}\n${LINK_V6}" || FULL_CLIP="$LINK_V6"
        echo -e "\033[1;36m[IPv6节点链接]\033[0m\n$LINK_V6"
    }
    echo -e "\033[1;34m==========================================\033[0m"
    [ -n "$FULL_CLIP" ] && copy_to_clipboard "$FULL_CLIP"
}

display_system_status() {
    local VER_INFO=$(/usr/bin/sing-box version 2>/dev/null | head -n1 | sed 's/version /v/')
    local CWND_VAL=$(ip route show default | grep -oE "initcwnd [0-9]+" | awk '{print $2}' || echo "10")
    echo -e "系统版本: \033[1;33m$OS_DISPLAY\033[0m"
    echo -e "内核信息: \033[1;33m$VER_INFO\033[0m"
    echo -e "优化级别: \033[1;32m${SBOX_OPTIMIZE_LEVEL:-未检测}\033[0m"
    echo -e "Initcwnd: \033[1;33m${CWND_VAL} (已强化)\033[0m"
    echo -e "推荐带宽: \033[1;33m${SBOX_MAX_BW_DOWN:-0} Mbps\033[0m"
    echo -e "伪装SNI:  \033[1;33m${RAW_SNI:-未检测}\033[0m"
}

# ==========================================
# 管理脚本生成
# ==========================================
create_sb_tool() {
    cat > "$SBOX_CORE" <<EOF
#!/usr/bin/env bash
set -euo pipefail
SBOX_GOLIMIT='$SBOX_GOLIMIT'
SBOX_GOGC='$SBOX_GOGC'
SBOX_MEM_MAX='$SBOX_MEM_MAX'
SBOX_MEM_HIGH='$SBOX_MEM_HIGH'
SBOX_GOMAXPROCS='${SBOX_GOMAXPROCS:-}'
SBOX_OPTIMIZE_LEVEL='$SBOX_OPTIMIZE_LEVEL'
VAR_SYSTEMD_NICE='$VAR_SYSTEMD_NICE'
VAR_SYSTEMD_IOSCHED='$VAR_SYSTEMD_IOSCHED'
SBOX_MAX_BW_UP='$SBOX_MAX_BW_UP'
SBOX_MAX_BW_DOWN='$SBOX_MAX_BW_DOWN'
RAW_IP4='${RAW_IP4:-}'
RAW_IP6='${RAW_IP6:-}'
EOF
    declare -f is_valid_port prompt_for_port get_env_data display_links display_system_status detect_os copy_to_clipboard create_config setup_service install_singbox info err warn succ optimize_system >> "$SBOX_CORE"

    cat >> "$SBOX_CORE" <<'EOF'
if [[ "${1:-}" == "--show-only" ]]; then
    detect_os && get_env_data
    echo -e "\n\033[1;34m==========================================\033[0m"
    display_system_status && echo -e "\033[1;34m------------------------------------------\033[0m"
    display_links
elif [[ "${1:-}" == "--reset-port" ]]; then
    detect_os && optimize_system && create_config "$2" && setup_service && sleep 1 && get_env_data && display_links
elif [[ "${1:-}" == "--update-kernel" ]]; then
    detect_os
    if install_singbox "update"; then optimize_system && setup_service && succ "内核已更新"; fi
fi
EOF
    chmod 700 "$SBOX_CORE"
    cat > "/usr/local/bin/sb" <<'EOF'
#!/usr/bin/env bash
CORE="/etc/sing-box/core_script.sh"
source "$CORE" --detect-only >/dev/null 2>&1
service_ctrl() { if [ -f /etc/init.d/sing-box ]; then rc-service sing-box $1; else systemctl $1 sing-box; fi; }
while true; do
    echo "=========================="
    echo " Sing-box HY2 管理 (快捷键: sb)"
    echo "=========================="
    echo "1. 查看信息   5. 重启服务"
    echo "2. 修改配置   6. 卸载脚本"
    echo "3. 重置端口   0. 退出"
    echo "4. 更新内核"
    echo "=========================="
    read -r -p "请选择 [0-6]: " opt
    case "$opt" in
        1) source "$CORE" --show-only; read -p "回车继续...";;
        2) vi /etc/sing-box/config.json && service_ctrl restart;;
        3) NEW_PORT=$(prompt_for_port); source "$CORE" --reset-port "$NEW_PORT"; read -p "回车继续...";;
        4) source "$CORE" --update-kernel; read -p "回车继续...";;
        5) service_ctrl restart && echo "已重启"; read -p "回车继续...";;
        6) read -p "确认卸载? (y/n): " cf; [[ "$cf" == "y" ]] && { service_ctrl stop; rm -rf /etc/sing-box /usr/bin/sing-box /usr/local/bin/sb "$CORE"; exit 0; };;
        0) exit 0;;
    esac
done
EOF
    chmod +x "/usr/local/bin/sb"
}

# ==========================================
# 主运行逻辑
# ==========================================
detect_os
[ "$(id -u)" != "0" ] && err "请使用 root 运行" && exit 1
install_dependencies
get_network_info
echo -e "-----------------------------------------------"
USER_PORT=$(prompt_for_port)
test_bandwidth     # 执行 iperf3 测速
optimize_system    # 计算差异化优化参数 (整合 QUIC 调度)
install_singbox "install"
generate_cert
create_config "$USER_PORT"
setup_service      # 应用 Systemd 优化
create_sb_tool     # 生成管理脚本

get_env_data
echo -e "\n\033[1;34m==========================================\033[0m"
display_system_status
echo -e "\033[1;34m------------------------------------------\033[0m"
display_links
info "脚本部署完毕，输入 'sb' 管理"
