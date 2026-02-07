#!/usr/bin/env bash
set -euo pipefail

# ==========================================
# 基础变量声明与环境准备
# ==========================================
SBOX_ARCH="";            OS_DISPLAY="";          SBOX_CORE="/etc/sing-box/core_script.sh"
SBOX_GOLIMIT="48MiB";    SBOX_GOGC="100";        SBOX_MEM_MAX="55M";     SBOX_OPTIMIZE_LEVEL="未检测"
SBOX_MEM_HIGH="42M";     CPU_CORE="1";           INITCWND_DONE="false";  VAR_DEF_MEM="";      USER_PORT=""
VAR_UDP_RMEM="";         VAR_UDP_WMEM="";        VAR_SYSTEMD_NICE="";    VAR_HY2_BW="200";    RAW_SALA=""
VAR_SYSTEMD_IOSCHED="";  SWAPPINESS_VAL="10";    BUSY_POLL_VAL="0";      VAR_BACKLOG="5000";  UDP_MEM_SCALE=""

TLS_DOMAIN_POOL=("www.bing.com" "www.microsoft.com" "itunes.apple.com" "www.icloud.com" "www.7-zip.org" "www.jsdelivr.com")
pick_tls_domain() { echo "${TLS_DOMAIN_POOL[$RANDOM % ${#TLS_DOMAIN_POOL[@]}]}"; }
TLS_DOMAIN="$(pick_tls_domain)"

# ==========================================
# 彩色输出与工具函数
# ==========================================
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }
succ() { echo -e "\033[1;32m[OK]\033[0m $*"; }

# OSC 52 自动复制到剪贴板函数 (支持多行)
copy_to_clipboard() {
    local content="$1"
    if [ -n "${SSH_TTY:-}" ] || [ -n "${DISPLAY:-}" ]; then
        local b64_content=$(printf "%b" "$content" | base64 | tr -d '\r\n')
        echo -ne "\033]52;c;${b64_content}\a"
        echo -e "\033[1;32m[复制]\033[0m 节点链接已推送至本地剪贴板"
    fi
}

# 侦测系统类型
detect_os() {
    if [ -f /etc/os-release ]; then . /etc/os-release; OS_DISPLAY="${PRETTY_NAME:-$ID}"; ID="${ID:-}"; ID_LIKE="${ID_LIKE:-}"; else OS_DISPLAY="Unknown Linux"; ID="unknown"; ID_LIKE=""; fi
    # 增强判定逻辑
    if [ -f /etc/alpine-release ]; then OS="alpine"; elif [ -f /etc/debian_version ]; then OS="debian"; elif [ -f /etc/redhat-release ]; then OS="redhat"; else
        local COMBINED="${ID} ${ID_LIKE}"; case "$COMBINED" in *[Aa][Ll][Pp][Ii][Nn][Ee]*) OS="alpine" ;; *[Dd][Ee][Bb][Ii][Aa][Nn]*|*[Uu][Bb][Uu][Nn][Tt][Uu]*) OS="debian" ;; *[Cc][Ee][Nn][Tt][Oo][Ss]*|*[Rr][Hh][Ee][Ll]*|*[Ff][Ee][Dd][Oo][Rr][Aa]*) OS="redhat" ;; *) OS="unknown" ;; esac
    fi
    # 环境修复与架构匹配
    [ "$OS" = "alpine" ] && { [ -x /sbin/syslogd ] && [ ! -f /var/run/syslogd.pid ] && syslogd >/dev/null 2>&1 || true; }
    case "$(uname -m)" in x86_64) SBOX_ARCH="amd64" ;; aarch64) SBOX_ARCH="arm64" ;; armv7l) SBOX_ARCH="armv7" ;; i386|i686) SBOX_ARCH="386" ;; *) err "不支持的架构: $(uname -m)"; exit 1 ;; esac
}

# 依赖安装 (容错增强版)
install_dependencies() {
    info "正在检查系统类型..."
    local PM="" DEPS="curl jq openssl ca-certificates bash tzdata tar iproute2 iptables procps netcat-openbsd" OPT="ethtool kmod wireguard-tools"
    if command -v apk >/dev/null 2>&1; then PM="apk"; DEPS="$DEPS coreutils util-linux-misc"
    elif command -v apt-get >/dev/null 2>&1; then PM="apt"; DEPS="$DEPS util-linux"
    else PM="yum"; DEPS="${DEPS//netcat-openbsd/nc}"; DEPS="${DEPS//procps/procps-ng} util-linux"; fi
    [ -w /proc/sys/vm/drop_caches ] && sync && echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    case "$PM" in
        apk) info "检测到 Alpine 系统，执行分批安装依赖..."
             apk update >/dev/null 2>&1
             local missing=""; for pkg in $DEPS; do apk info -e "$pkg" >/dev/null || missing="$missing $pkg"; done
             [ -n "$missing" ] && apk add --no-cache $missing || warn "部分组件安装异常"
             missing=""; for pkg in $OPT; do apk info -e "$pkg" >/dev/null || missing="$missing $pkg"; done
             [ -n "$missing" ] && apk add --no-cache $missing >/dev/null 2>&1 || true
             rm -rf /var/cache/apk/* ;;
        apt) info "检测到 Debian/Ubuntu 系统，正在更新源并安装依赖..."
             export DEBIAN_FRONTEND=noninteractive
             apt-get update -y >/dev/null 2>&1
             apt-get install -y --no-install-recommends $DEPS || err "依赖安装失败"
             apt-get install -y --no-install-recommends $OPT >/dev/null 2>&1 || true
             apt-get clean; rm -rf /var/lib/apt/lists/* ;;
        yum) info "检测到 RHEL/CentOS 系统，正在同步仓库并安装依赖..."
             $(command -v dnf || echo "yum") install -y $DEPS || err "依赖安装失败"
             $(command -v dnf || echo "yum") install -y $OPT >/dev/null 2>&1 || true ;;
    esac
    update-ca-certificates 2>/dev/null || true
    for cmd in jq curl tar bash pgrep taskset; do command -v "$cmd" >/dev/null 2>&1 || { [ "$PM" = "apk" ] && apk add --no-cache util-linux >/dev/null 2>&1 || { err "核心依赖 ${cmd} 安装失败，请检查网络或源"; exit 1; }; } done
    succ "所需依赖已就绪"
}

# 检测CPU核心数
get_cpu_core() {
    local n q p c; n=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo || echo 1)
    if [ -r /sys/fs/cgroup/cpu.max ]; then
        read -r q p < /sys/fs/cgroup/cpu.max
    else
        q=$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us 2>/dev/null)
        p=$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us 2>/dev/null)
    fi
    if [[ "${q:-}" =~ ^[0-9]+$ ]] && [ "$q" -gt 0 ]; then
        p=${p:-100000}; c=$(( q / p )); [ "$c" -le 0 ] && c=1
        echo $(( c < n ? c : n ))
    else echo "$n"; fi
}

# 获取并校验端口 (范围：1025-65535)
prompt_for_port() {
    local p rand
    while :; do
        read -r -p "请输入端口 [1025-65535] (回车随机生成): " p
        if [ -z "$p" ]; then
            if command -v shuf >/dev/null 2>&1; then p=$(shuf -i 1025-65535 -n 1)
            elif [ -r /dev/urandom ] && command -v od >/dev/null 2>&1; then rand=$(od -An -N2 -tu2 /dev/urandom | tr -d ' '); p=$((1025 + rand % 64511))
            else p=$((1025 + RANDOM % 64511)); fi
        fi
        if [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 1025 ] && [ "$p" -le 65535 ]; then
            local occupied=""
            if command -v ss >/dev/null 2>&1; then occupied=$(ss -tunlp | grep -w ":$p")
            elif command -v netstat >/dev/null 2>&1; then occupied=$(netstat -tunlp | grep -w ":$p")
            elif command -v lsof >/dev/null 2>&1; then occupied=$(lsof -i :"$p")
            fi
            if [ -n "$occupied" ]; then
                echo -e "\033[1;33m[WARN]\033[0m 端口 $p 已被占用，请更换端口或直接回车重新生成" >&2
                p=""; continue
            fi
            echo -e "\033[1;32m[INFO]\033[0m 使用端口: $p" >&2
            echo "$p"; return 0
        else
            echo -e "\033[1;31m[错误]\033[0m 端口无效，请输入1025-65535之间的数字" >&2
        fi
    done
}

# 生成 ECC P-256 高性能证书
generate_cert() {
    local CERT_DIR="/etc/sing-box/certs"
    [ -f "$CERT_DIR/fullchain.pem" ] && return 0
    info "生成 ECC P-256 高性能证书..."
    mkdir -p "$CERT_DIR" && chmod 700 "$CERT_DIR"
    
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$CERT_DIR/privkey.pem" -out "$CERT_DIR/fullchain.pem" \
        -days 3650 -sha256 -subj "/CN=$TLS_DOMAIN" \
        -addext "basicConstraints=critical,CA:FALSE" \
        -addext "subjectAltName=DNS:$TLS_DOMAIN,DNS:*.$TLS_DOMAIN" \
        -addext "extendedKeyUsage=serverAuth" &>/dev/null || {
        # 兼容老版本：去除扩展重试
        openssl req -x509 -newkey ec:<(openssl ecparam -name prime256v1) -nodes \
            -keyout "$CERT_DIR/privkey.pem" -out "$CERT_DIR/fullchain.pem" \
            -days 3650 -subj "/CN=$TLS_DOMAIN" &>/dev/null
    }

    [ -s "$CERT_DIR/fullchain.pem" ] && {
        openssl x509 -in "$CERT_DIR/fullchain.pem" -noout -sha256 -fingerprint | cut -d'=' -f2 | tr -d ': ' | tr '[:upper:]' '[:lower:]' > "$CERT_DIR/cert_fingerprint.txt"
        chmod 600 "$CERT_DIR"/*.pem; succ "ECC 证书就绪"
    } || { err "证书生成失败"; exit 1; }
}

# 获取公网IP
get_network_info() {
    info "获取网络信息..."
    RAW_IP4=""; RAW_IP6=""; IS_V6_OK="false"
    local t4="/tmp/.v4" t6="/tmp/.v6"
    rm -f "$t4" "$t6"
    _f() { 
        local p=$1
        { curl $p -ksSfL --connect-timeout 3 --max-time 5 "https://1.1.1.1/cdn-cgi/trace" | awk -F= '/ip/ {print $2}'; } || \
        curl $p -ksSfL --connect-timeout 3 --max-time 5 "https://api.ipify.org" || \
        curl $p -ksSfL --connect-timeout 3 --max-time 5 "https://ifconfig.me" || echo ""
    }
    # 并发执行
    _f -4 >"$t4" 2>/dev/null & p4=$!; _f -6 >"$t6" 2>/dev/null & p6=$!; wait $p4 $p6 2>/dev/null
    # 数据清洗
    [ -s "$t4" ] && RAW_IP4=$(tr -d '[:space:]' < "$t4" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || echo "")
    [ -s "$t6" ] && RAW_IP6=$(tr -d '[:space:]' < "$t6" | grep -Ei '([a-f0-9:]+:+)+[a-f0-9]+' || echo "")
    rm -f "$t4" "$t6"
    # 状态判定：只有 RAW_IP6 真的包含冒号才判定 IPv6 可用
    [[ "$RAW_IP6" == *:* ]] && IS_V6_OK="true" || IS_V6_OK="false"
    # 错误退出判断
    [ -z "$RAW_IP4" ] && [ -z "$RAW_IP6" ] && { err "错误: 未能探测到任何有效的公网 IP，安装中断"; exit 1; }
    # 原有输出信息保持不变
    [ -n "$RAW_IP4" ] && succ "IPv4: $RAW_IP4 [✔]" || info "IPv4: 不可用 (单栈 IPv6 环境)"
    [ "$IS_V6_OK" = "true" ] && succ "IPv6: $RAW_IP6 [✔]" || info "IPv6: 不可用 (单栈 IPv4 环境)"
}

# 网络延迟探测模块
probe_network_rtt() {
    local rtt_val; local loss_val="5"; local real_rtt_factors="130"; local loss_compensation="100"; set +e
    echo -e "\033[1;34m[INFO]\033[0m 正在探测网络画像 (RTT/丢包)..." >&2
	# 1. 扩充探测池：覆盖国内骨干、全球顶级 CDN 及 DNS 节点
    local targets=("223.5.5.5" "119.29.29.29" "114.114.114.114" "1.1.1.1" "8.8.8.8" "8.26.56.26" "208.67.222.222")
    local ping_res=""
	# 2. 遍历探测：获取首个有效响应，平衡探测速度与覆盖广度
    for target in "${targets[@]}"; do
        local res=$(ping -c 5 -W 1 "$target" 2>/dev/null)
        if echo "$res" | grep -q "received"; then ping_res="$res"; break; fi
    done
	# 3. 提取平均 RTT 并解析丢包率 (兼容多系统格式)
    if [ -n "$ping_res" ]; then
        rtt_val=$(echo "$ping_res" | awk -F'/' 'END{print int($5)}')
        loss_val=$(echo "$ping_res" | grep -oE '[0-9]+% packet loss' | grep -oE '[0-9]+' || echo "5")
        echo -e "\033[1;32m[OK]\033[0m 实测 RTT: ${rtt_val}ms | 丢包: ${loss_val}%" >&2
    else
        rtt_val="150"; echo -e "\033[1;33m[WARN]\033[0m 探测受阻，应用全球预估值: 150ms" >&2
    fi
    set -e
    # 画像联动赋值
    real_rtt_factors=$(( rtt_val + 100 ))   # 延迟补偿：实测值 + 100ms (平衡握手开销)
	# 丢包补偿：每 1% 丢包增加 5% 缓冲区冗余，最高 200%
    loss_compensation=$(( 100 + loss_val * 5 )); [ "$loss_compensation" -gt 200 ] && loss_compensation=200
	# 输出原始 RTT 供脚本其它函数引用
    echo "$rtt_val" "$real_rtt_factors" "$loss_compensation"
}

# 内存资源探测模块
probe_memory_total() {
    local mem_total=64 mem_cgroup=0
    local mem_host_total=$(free -m | awk '/Mem:/ {print $2}' | tr -cd '0-9')
    # 1. 优先级探测: Cgroup v1 -> Cgroup v2 -> /proc/meminfo
    if [ -f /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        local m_limit=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes | tr -cd '0-9')
        [ "${#m_limit}" -lt 15 ] && mem_cgroup=$((m_limit / 1024 / 1024))
    elif [ -f /sys/fs/cgroup/memory.max ]; then
        local m_max=$(cat /sys/fs/cgroup/memory.max | tr -cd '0-9')
        [ -n "$m_max" ] && mem_cgroup=$((m_max / 1024 / 1024))
    elif grep -q "MemTotal" /proc/meminfo; then
        mem_cgroup=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
    fi
    # 2. 内存边界判定与特殊虚拟化 (OpenVZ) 修正
    [ "$mem_cgroup" -gt 0 ] && [ "$mem_cgroup" -le "$mem_host_total" ] && mem_total=$mem_cgroup || mem_total=$mem_host_total
    [ -f /proc/user_beancounters ] && mem_total=$mem_host_total
    # 3. 最终异常值校验 (兜底 64MB)
    ([ -z "$mem_total" ] || [ "$mem_total" -le 0 ] || [ "$mem_total" -gt 64000 ]) && mem_total=64
    echo "$mem_total"
}

# InitCWND 专项优化模块 (取黄金分割点 15 ，比默认 10 强 50%，比 20 更隐蔽)
apply_initcwnd_optimization() {
    local silent="${1:-false}" info gw dev mtu mss opts
    command -v ip >/dev/null || return 0
    local current_route=$(ip route show default | head -n1)
    # 幂等性检查：若已包含 initcwnd 15 则跳过
    echo "$current_route" | grep -q "initcwnd 15" && { [[ "$silent" == "false" ]] && info "InitCWND 已优化，跳过"; INITCWND_DONE="true"; return 0; }

    # 提取核心路由参数
    gw=$(echo "$current_route" | grep -oE 'via [^ ]+' | awk '{print $2}')
    dev=$(echo "$current_route" | grep -oE 'dev [^ ]+' | awk '{print $2}')
    mtu=$(echo "$current_route" | grep -oE 'mtu [0-9]+' | awk '{print $2}' || echo 1500)
    mss=$((mtu - 40))
    opts="initcwnd 15 initrwnd 15 advmss $mss"

    # 执行修改（逻辑依然采用你的高效尝试链）
    if { [ -n "$gw" ] && [ -n "$dev" ] && ip route change default via "$gw" dev "$dev" $opts 2>/dev/null; } || \
       { [ -n "$gw" ] && [ -n "$dev" ] && ip route replace default via "$gw" dev "$dev" $opts 2>/dev/null; } || \
       { [ -n "$dev" ] && ip route replace default dev "$dev" $opts 2>/dev/null; } || \
       ip route change default $opts 2>/dev/null; then
        INITCWND_DONE="true"
        [[ "$silent" == "false" ]] && succ "InitCWND 优化成功 (15/MSS $mss)"
    else
        [[ "$silent" == "false" ]] && warn "InitCWND 修改失败（内核或容器限制）"
    fi
}

# ZRAM/Swap 智能配置
setup_zrm_swap() {
    local mt="$1" zs z_bytes st algo="lz4"
    [ -z "$mt" ] || [ "$mt" -ge 600 ] && return 0  
    grep -q "zram0" /proc/swaps && { info "ZRAM 已就绪"; return 0; }
	
    if ! modprobe zram 2>/dev/null; then [ "$OS" = "alpine" ] && apk add linux-virt-modules >/dev/null 2>&1 && modprobe zram 2>/dev/null; fi
    if ! modprobe zram 2>/dev/null; then warn "内核不支持 ZRAM"; elif [ ! -b /dev/zram0 ]; then warn "未发现 ZRAM 设备"; else
        if ! echo 1 > /sys/block/zram0/reset 2>/dev/null; then warn "容器限制，ZRAM 不可用"; else
            zs=$((mt * 15 / 10)); [ "$zs" -gt 512 ] && zs=512; z_bytes=$((zs * 1024 * 1024))
            [ -f /sys/block/zram0/comp_algorithm ] && { grep -qw lz4 /sys/block/zram0/comp_algorithm && algo="lz4" || algo="lzo"; echo "$algo" > /sys/block/zram0/comp_algorithm 2>/dev/null || true; }
            if echo "$z_bytes" > /sys/block/zram0/disksize 2>/dev/null && mkswap /dev/zram0 >/dev/null 2>&1 && swapon -p 10 /dev/zram0 2>/dev/null; then
                succ "ZRAM 激活: ${zs}M ($algo)"; [ "$mt" -le 128 ] && sysctl -w vm.swappiness=80 >/dev/null 2>&1
                if command -v systemctl >/dev/null 2>&1; then
                    cat > /etc/systemd/system/zram-swap.service <<EOF
[Unit]
Description=ZRAM Swap
Before=sing-box.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'modprobe zram; echo $algo > /sys/block/zram0/comp_algorithm; echo $z_bytes > /sys/block/zram0/disksize; mkswap /dev/zram0; swapon -p 10 /dev/zram0'
ExecStop=/sbin/swapoff /dev/zram0
[Install]
WantedBy=multi-user.target
EOF
                    systemctl daemon-reload && systemctl enable zram-swap.service 2>/dev/null
                elif [ "$OS" = "alpine" ]; then
                    cat > /etc/init.d/zram-swap <<EOF
#!/sbin/openrc-run
start() { modprobe zram; echo $algo > /sys/block/zram0/comp_algorithm; echo $z_bytes > /sys/block/zram0/disksize; mkswap /dev/zram0 && swapon -p 10 /dev/zram0; }
stop() { swapoff /dev/zram0; echo 1 > /sys/block/zram0/reset; }
EOF
                    chmod +x /etc/init.d/zram-swap && rc-update add zram-swap default 2>/dev/null
                fi; return 0
            else warn "ZRAM 初始化失败"; fi
        fi
    fi
	# 磁盘 Swap 兜底 (仅在 ZRAM 失败且非 Alpine 时)
    [ "$OS" = "alpine" ] && { info "Alpine 跳过磁盘 Swap"; return 0; }
	local st=$(grep "SwapTotal" /proc/meminfo | awk '{print $2}')
    if [ "${st:-0}" -eq 0 ] && [ ! -d /proc/vz ]; then
        info "创建磁盘 Swap (512M)..."
        if (fallocate -l 512M /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=512 2>/dev/null) && chmod 600 /swapfile && mkswap /swapfile >/dev/null 2>&1 && swapon -p 5 /swapfile 2>/dev/null; then
            grep -q "/swapfile" /etc/fstab || echo "/swapfile swap swap pri=5 0 0" >> /etc/fstab && succ "磁盘 Swap 已激活"
        else rm -f /swapfile 2>/dev/null; warn "磁盘 Swap 创建失败"; fi
    fi
}

# 动态 RTT 内存页钳位
safe_rtt() {
    local dyn_buf="$1" rtt_val="$2" max_udp_pages="$3" udp_min="$4" udp_pre="$5" udp_max="$6" real_rtt_factors="$7" loss_compensation="$8"
    local dyn_pages=$(( dyn_buf / 4096 ))
    # 1. 计算探测 BDP：使用补偿后的画像值及丢包补偿系数
    local probe_pages=$(( real_rtt_factors * 1024 * loss_compensation / 100 ))
    # 2. 仲裁逻辑：探测值与 dyn_buf 保底值取最大者
    rtt_scale_max=$(( probe_pages > dyn_pages ? probe_pages : dyn_pages ))
    # 3. 延迟梯度补偿：根据实测 RTT 自动切换模式
    if [ "$rtt_val" -ge 150 ]; then
        rtt_scale_max=$(( rtt_scale_max * 15 / 10 )); SBOX_OPTIMIZE_LEVEL="${SBOX_OPTIMIZE_LEVEL} (QUIC远航)"
    else
        SBOX_OPTIMIZE_LEVEL="${SBOX_OPTIMIZE_LEVEL} (QUIC竞速)"
    fi
    # 4. 生成三级梯度 (1.0 : 0.9 : 0.75) 与多级防护
    rtt_scale_pressure=$(( rtt_scale_max * 90 / 100 )); rtt_scale_min=$(( rtt_scale_max * 75 / 100 ))
	# 激进内存保护 (当超过该档位设定的最大页数时钳位)
    if [ "$rtt_scale_max" -gt "$max_udp_pages" ]; then
        rtt_scale_max=$max_udp_pages; rtt_scale_pressure=$(( max_udp_pages * 95 / 100 )); rtt_scale_min=$(( max_udp_pages * 80 / 100 ))
    fi
    # 5. 系统全局硬上限最终防护
    rtt_scale_max=$(( rtt_scale_max < udp_max ? rtt_scale_max : udp_max ))
    rtt_scale_pressure=$(( rtt_scale_pressure < udp_pre ? rtt_scale_pressure : udp_pre ))
    rtt_scale_min=$(( rtt_scale_min < udp_min ? rtt_scale_min : udp_min ))
}

# sing-box 用户态运行时调度人格（Go/QUIC/缓冲区自适应）
apply_userspace_adaptive_profile() {
    local g_procs="$1" wnd="$2" buf="$3" real_c="$4" mem_total="$5"
    # === 1. P 处理器调度 (针对单核小鸡的特殊优化) ===
    # 如果是单核，强行给 2 个 P 能够让网络 IO 和内存回收并行，不至于卡死
    [ "$real_c" -eq 1 ] && export GOMAXPROCS=2 || export GOMAXPROCS="$g_procs"
    # === 2. 内存回收策略分级 (76M+- 差异化处理) ===
    [ "$mem_total" -lt 76 ] && \
    { export GODEBUG="madvdontneed=1,scavenge_target=1"; info "Runtime → 激进回收模式 (76m-)"; } || \
    { export GODEBUG="madvdontneed=1,asyncpreemptoff=1"; info "Runtime → 性能优先模式 (76m+)"; }
    export GOMEMLIMIT="${SBOX_GOLIMIT:-48MiB}" GOGC="${SBOX_GOGC:-100}"
    export SINGBOX_QUIC_MAX_CONN_WINDOW="$wnd" VAR_HY2_BW="${VAR_HY2_BW:-200}"
    export SINGBOX_UDP_RECVBUF="$buf" SINGBOX_UDP_SENDBUF="$buf"
    # 针对 100M- 小鸡执行最后一道严谨校准 (Sanity Check)
    if [ "$mem_total" -lt 100 ]; then
        local soft_line=$(( mem_total - 26 )) # 预留 28M 红线
        [ "$soft_line" -lt 34 ] && soft_line=34 # 绝对启动底线
        # 如果当前全局变量值超过红线，则强制钳位
        [ "$(echo "$GOMEMLIMIT" | tr -dc '0-9')" -gt "$soft_line" ] && \
        export GOMEMLIMIT="${soft_line}MiB" GOGC="100"
    fi
    # === 3. 持久化配置 (修复潜在变量引用问题) ===
    mkdir -p /etc/sing-box
    cat > /etc/sing-box/env <<EOF
GOMAXPROCS=$GOMAXPROCS
GOGC=$GOGC
GOMEMLIMIT=$GOMEMLIMIT
GODEBUG=$GODEBUG
SINGBOX_QUIC_MAX_CONN_WINDOW=$SINGBOX_QUIC_MAX_CONN_WINDOW
SINGBOX_UDP_RECVBUF=$buf
SINGBOX_UDP_SENDBUF=$buf
VAR_HY2_BW=$VAR_HY2_BW
EOF
    chmod 644 /etc/sing-box/env
    # === 4. CPU 亲和力优化 (绑定当前脚本到所有可用核心) ===
    [ "$real_c" -gt 1 ] && command -v taskset >/dev/null 2>&1 && taskset -pc 0-$((real_c - 1)) $$ >/dev/null 2>&1
    info "Runtime → GOMAXPROCS: $GOMAXPROCS 核 | 内存限额: $GOMEMLIMIT | GOGC: $GOGC | Buffer: $((buf/1024)) KB"
}

# 网卡核心负载加速（RPS/XPS/批处理密度）
apply_nic_core_boost() {
    # 1. 寻找默认出口网卡
    local IFACE=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')
    [ -z "$IFACE" ] && return 0
    local real_c="$1" bgt="$2" usc="$3"	
	# 2. 内核软中断预算优化
    sysctl -w net.core.netdev_budget="$bgt" net.core.netdev_budget_usecs="$usc" >/dev/null 2>&1 || true
    # 3. 驱动识别与发送队列 (TXQLEN) 动态调整
    local driver=""
    [ -L "/sys/class/net/$IFACE/device/driver" ] && driver=$(basename "$(readlink "/sys/class/net/$IFACE/device/driver")")
    local target_qlen=10000
    case "$driver" in
        virtio_net|veth|"") target_qlen=5000 ;;  # 虚拟化环境降低队列深度，减少内存抖动
        *) target_qlen=10000 ;;
    esac
	# 4. 链路层特征与硬件卸载优化
	if [ -d "/sys/class/net/$IFACE" ]; then
        ip link set dev "$IFACE" txqueuelen "$target_qlen" 2>/dev/null || true     
        if command -v ethtool >/dev/null 2>&1; then
            ethtool -K "$IFACE" gro on gso on tso on lro off 2>/dev/null || true
            local tuned_usc=100
            [ "$real_c" -ge 2 ] && tuned_usc=150   # 大幅提升中断延迟阈值 (20 -> 100+)，牺牲 0.1ms 延迟，但能救活 CPU，对吞吐量至关重要
            ethtool -C "$IFACE" rx-usecs "$tuned_usc" tx-usecs "$tuned_usc" 2>/dev/null || true
            ethtool -G "$IFACE" rx 2048 tx 2048 2>/dev/null || true
        fi
    fi
    # 5. 多核分发优化 (RPS/XPS)：解决单核处理瓶颈
    if [ "$real_c" -ge 2 ] && [ -d "/sys/class/net/$IFACE/queues" ]; then
        local MASK=$(printf '%x' $(( (1<<real_c)-1 )))
		# 接收端分发 (RPS)
        for q in /sys/class/net/"$IFACE"/queues/rx-*/rps_cpus; do
            [ -w "$q" ] && echo "$MASK" > "$q" 2>/dev/null || true
        done
		# 发送端分发 (XPS)
        for q in /sys/class/net/"$IFACE"/queues/tx-*/xps_cpus; do
            [ -w "$q" ] && echo "$MASK" > "$q" 2>/dev/null || true
        done
    fi
	info "NIC 优化 → 网卡: $IFACE | QLen: $target_qlen | 中断延迟: ${tuned_usc:-default} us"
}

#防火墙开放端口
apply_firewall() {
    local port=$(jq -r '.inbounds[0].listen_port // empty' /etc/sing-box/config.json 2>/dev/null)
    [ -z "$port" ] && return 0
    {   if command -v ufw >/dev/null 2>&1; then ufw allow "$port"/udp >/dev/null 2>&1
        elif command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --list-ports | grep -q "$port/udp" || { firewall-cmd --add-port="$port"/udp --permanent; firewall-cmd --reload; } >/dev/null 2>&1
        elif command -v iptables >/dev/null 2>&1; then
            iptables -D INPUT -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1; iptables -I INPUT -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1
            command -v ip6tables >/dev/null 2>&1 && { ip6tables -D INPUT -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1; ip6tables -I INPUT -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1; }
        fi    } || true
}
	
# "全功能调度器"
service_ctrl() {
    local action="$1"
    [[ "$action" == "restart" ]] && { echo -e "\033[1;32m[INFO]\033[0m 正在应用调优并重启服务，请稍后..."; optimize_system >/dev/null 2>&1 || true; setup_service; apply_firewall; return 0; }
    if [ -x "/etc/init.d/sing-box" ]; then rc-service sing-box "$action"
    else systemctl daemon-reload >/dev/null 2>&1; systemctl "$action" sing-box; fi
}

# ==========================================
# 系统内核优化 (核心逻辑：差异化 + 进程调度 + UDP极限)
# ==========================================
optimize_system() {
    local rtt_res=($(probe_network_rtt)); local mem_total=$(probe_memory_total)
	local rtt_avg="${rtt_res[0]:-150}" real_rtt_factors="${rtt_res[1]:-130}" loss_compensation="${rtt_res[2]:-100}"
    local real_c="$CPU_CORE" ct_max=16384 ct_udp_to=30 ct_stream_to=30
    local dyn_buf g_procs g_wnd g_buf net_bgt net_usc tcp_rmem_max
    local max_udp_mb max_udp_pages udp_mem_global_min udp_mem_global_pressure udp_mem_global_max
    local swappiness_val="${SWAPPINESS_VAL:-10}" busy_poll_val="${BUSY_POLL_VAL:-0}"
    
    setup_zrm_swap "$mem_total"
	info "系统画像: CPU核心: ${real_c} 核 | 系统内存: ${mem_total} mb | 平均延迟: ${rtt_avg} ms | RTT补偿: ${real_rtt_factors} ms | 丢包补偿: ${loss_compensation}%"

    # 阶段一： 四档位差异化配置
    if [ "$mem_total" -ge 450 ]; then
        VAR_HY2_BW="500"; max_udp_mb=$((mem_total * 66 / 100))
        SBOX_GOLIMIT="$((mem_total * 76 / 100))MiB"; SBOX_GOGC="200"
        SBOX_MEM_HIGH="$((mem_total * 86 / 100))M"; SBOX_MEM_MAX="$((mem_total * 96 / 100))M"
        VAR_SYSTEMD_NICE="-15"; VAR_SYSTEMD_IOSCHED="realtime"; tcp_rmem_max=16777216
        g_procs=$real_c; swappiness_val=10; busy_poll_val=50; ct_max=65535; ct_stream_to=60
        SBOX_OPTIMIZE_LEVEL="512M 旗舰版"
    elif [ "$mem_total" -ge 200 ]; then
        VAR_HY2_BW="300"; max_udp_mb=$((mem_total * 63 / 100))
        SBOX_GOLIMIT="$((mem_total * 75 / 100))MiB"; SBOX_GOGC="150"
        SBOX_MEM_HIGH="$((mem_total * 85 / 100))M"; SBOX_MEM_MAX="$((mem_total * 95 / 100))M"
        VAR_SYSTEMD_NICE="-10"; VAR_SYSTEMD_IOSCHED="best-effort"; tcp_rmem_max=8388608
        g_procs=$real_c; swappiness_val=10; busy_poll_val=20; ct_max=32768; ct_stream_to=45
        SBOX_OPTIMIZE_LEVEL="256M 增强版"
    elif [ "$mem_total" -ge 100 ]; then
        VAR_HY2_BW="200"; max_udp_mb=$((mem_total * 60 / 100))
        SBOX_GOLIMIT="$((mem_total * 73 / 100))MiB"; SBOX_GOGC="130"
        SBOX_MEM_HIGH="$((mem_total * 83 / 100))M"; SBOX_MEM_MAX="$((mem_total * 93 / 100))M"
        VAR_SYSTEMD_NICE="-8"; VAR_SYSTEMD_IOSCHED="best-effort"; tcp_rmem_max=4194304
        swappiness_val=60; busy_poll_val=0; ct_max=16384; ct_stream_to=30
        [ "$real_c" -gt 2 ] && g_procs=2 || g_procs=$real_c
        SBOX_OPTIMIZE_LEVEL="128M 紧凑版"
    else
        VAR_HY2_BW="130"; max_udp_mb=$((mem_total * 56 / 100))
        SBOX_GOLIMIT="$((mem_total * 70 / 100))MiB"; SBOX_GOGC="100"
        SBOX_MEM_HIGH="$((mem_total * 80 / 100))M"; SBOX_MEM_MAX="$((mem_total * 90 / 100))M"
        VAR_SYSTEMD_NICE="-5"; VAR_SYSTEMD_IOSCHED="best-effort"; tcp_rmem_max=2097152
        g_procs=1; swappiness_val=100; busy_poll_val=0; ct_max=16384; ct_stream_to=30
        SBOX_OPTIMIZE_LEVEL="64M 激进版"
    fi

    # 阶段二：[重点] dyn_buf 跳板与带宽灵魂联动
    # 1. 计算带宽所需 BDP 保底 (系数3以应对国际链路抖动)
    local bdp_min=$(( VAR_HY2_BW * 1024 * 1024 / 8 / 5 * 3 )) # 约 0.3s 冗余
    # 2. 设置跳板变量 dyn_buf (综合物理能力与带宽需求)
    dyn_buf=$(( (mem_total << 20) >> 3 ))
    [ "$dyn_buf" -lt "$bdp_min" ] && dyn_buf=$bdp_min
    # 100M+ 机器给 32MB 爆发力保底；100M- 机器给 16MB 生存保底
    [ "$mem_total" -ge 100 ] && [ "$dyn_buf" -lt 33554432 ] && dyn_buf=33554432
    [ "$dyn_buf" -lt 16777216 ] && dyn_buf=16777216
    [ "$dyn_buf" -gt 67108864 ] && dyn_buf=67108864
	
    # 3. 所有内核网络参数基于 dyn_buf 伸缩
    VAR_UDP_RMEM="$dyn_buf"; VAR_UDP_WMEM="$dyn_buf"
    VAR_DEF_MEM=$(( dyn_buf / 4 ))
    VAR_BACKLOG=$(( VAR_HY2_BW * 50 ))   # 队列从30提到50，抗突发丢包
    [ "$VAR_BACKLOG" -lt 8192 ] && VAR_BACKLOG=8192

    # 4. 联动导出：Sing-box 应用层参数
    g_wnd=$(( VAR_HY2_BW * loss_compensation / 100 / 8 ))      # 激进窗口，应对 80ms+ 延迟（原为 /10）
    [ "$g_wnd" -lt 15 ] && g_wnd=15  # 调高起步窗口（原为 12）
    g_buf=$(( dyn_buf / 6 ))         # 应用层 buffer 设为跳板的 1/6（原为 /8）

    # 5. 确定系统全局 UDP 限制 (作为 safe_rtt 的参照系)
	udp_mem_global_min=$(( dyn_buf >> 12 ))
	udp_mem_global_pressure=$(( (dyn_buf << 1) >> 12 ))  # 2倍压力线
	udp_mem_global_max=$(( ((mem_total << 20) * 75 / 100) >> 12 ))   # 物理红线 75%
	max_udp_pages=$(( max_udp_mb << 8 ))

    # 6. 根据带宽目标设定基础预算：每 100M 带宽分配约 1000 的预算
    local base_budget=$(( VAR_HY2_BW * 15 / 10 * 10 ))  # 基础权重增加50%
    [ "$base_budget" -lt 2000 ] && base_budget=2000
    [ "$base_budget" -gt 6000 ] && base_budget=6000
    # 多核：单次少吃多餐，靠多核并行 / 单核：必须一次多处理点，减少中断切换的开销
    [ "$real_c" -ge 2 ] && { net_bgt=$base_budget; net_usc=2000; } || { net_bgt=$(( base_budget << 1 )); net_usc=6000; }

    # 7. 内存保命机制：动态预留内核紧急水位 (vm.min_free_kbytes)
    local min_free_val=$(( mem_total * 1024 * 4 / 100 ))  # 100M内存预留约4%
    [ "$min_free_val" -lt 4608 ] && min_free_val=4608     # 最小不低于 3MB  
    if [ "$mem_total" -gt 100 ]; then [ "$min_free_val" -gt 65536 ] && min_free_val=65536; fi
	
	# 9. 路况仲裁
    safe_rtt "$dyn_buf" "$rtt_avg" "$max_udp_pages" "$udp_mem_global_min" "$udp_mem_global_pressure" "$udp_mem_global_max" "$real_rtt_factors" "$loss_compensation"
    UDP_MEM_SCALE="$rtt_scale_min $rtt_scale_pressure $rtt_scale_max"
	apply_initcwnd_optimization "false"
    apply_userspace_adaptive_profile "$g_procs" "$g_wnd" "$g_buf" "$real_c" "$mem_total"
    apply_nic_core_boost "$real_c" "$net_bgt" "$net_usc"
    info "优化定档: $SBOX_OPTIMIZE_LEVEL | 带宽: ${VAR_HY2_BW} Mbps"
    info "网络蓄水池 (dyn_buf): $(( dyn_buf / 1024 / 1024 )) MB"
	
    # 阶段三： BBR 探测与内核锐化 (递进式锁定最强算法)
    local tcp_cca="cubic"; modprobe tcp_bbr tcp_bbr2 tcp_bbr3 >/dev/null 2>&1 || true
    local avail=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "cubic")
    if [[ "$avail" =~ "bbr3" ]]; then tcp_cca="bbr3"; succ "检测到 BBRv3，激活极致响应模式"
    elif [[ "$avail" =~ "bbr2" ]]; then tcp_cca="bbr2"; succ "检测到 BBRv2，激活平衡加速模式"
    elif [[ "$avail" =~ "bbr" ]]; then tcp_cca="bbr"; info "检测到 BBRv1，激活标准加速模式"
    else warn "内核不支持 BBR，切换至高兼容 Cubic 模式"; fi
    if sysctl net.core.default_qdisc 2>/dev/null | grep -q "fq"; then info "FQ 调度器已就绪"; else info "准备激活 FQ 调度器..."; fi
	
    # 阶段四： 写入 Sysctl 配置到 /etc/sysctl.d/99-sing-box.conf（避免覆盖 /etc/sysctl.conf）
    local SYSCTL_FILE="/etc/sysctl.d/99-sing-box.conf"
    cat > "$SYSCTL_FILE" <<SYSCTL
# === 一、 基础转发与内存管理 (含 ZRAM 与 OOM 策略) ===
net.ipv4.ip_forward = 1                    # 开启 IPv4 转发
net.ipv6.conf.all.forwarding = 1           # 开启 IPv6 转发
net.ipv6.conf.all.accept_ra = 2            # 强制接受 RA (解决转发模式下 IPv6 掉线)
net.ipv6.conf.default.accept_ra = 2        # 默认接受 RA
vm.swappiness = $swappiness_val            # 交换分区权重 (根据内存动态调整)
vm.min_free_kbytes = $min_free_val         # 强制预留水位 (防高并发内核卡死)
vm.dirty_ratio = 10                        # 内存脏数据占比上限
vm.dirty_background_ratio = 5              # 脏数据后台写入阈值
vm.overcommit_memory = 1                   # 允许内存超额分配
vm.panic_on_oom = 0                        # 内存溢出时不崩溃系统
$(grep -q "^/dev/zram0 " /proc/swaps 2>/dev/null && cat <<ZRAM_TUNING
vm.page-cluster = 0                        # ZRAM环境下禁用预读 (提升随机读写)
vm.vfs_cache_pressure = 500                # 积极回收文件缓存 (为网络腾内存)
ZRAM_TUNING
)

# === 二、 网络设备层与 CPU 调度 (核心网卡加速) ===
net.core.netdev_max_backlog = $VAR_BACKLOG # 接收队列深度 (防突发丢包)
net.core.dev_weight = 64                   # CPU 单次收包权重
net.core.busy_read = $busy_poll_val        # 繁忙轮询 (降低收包延迟)
net.core.busy_poll = $busy_poll_val        # 繁忙轮询 (针对UDP优化)
net.core.somaxconn = 8192                  # 监听队列上限
net.core.default_qdisc = fq                # BBR必备调度规则
net.core.netdev_budget = $net_bgt          # 调度预算 (单次轮询处理包数)
net.core.netdev_budget_usecs = $net_usc    # 调度时长 (单次轮询微秒上限)
net.core.netdev_tstamp_prequeue = 0        # 禁用时间戳预处理 (降延迟)

# === 三、 协议栈缓冲与自适应加速 (TCP/UDP/BBR/MTU) ===
# --- 全局缓冲区限制 ---
net.core.rmem_default = $VAR_DEF_MEM       # 默认读缓存
net.core.wmem_default = $VAR_DEF_MEM       # 默认写缓存
net.core.rmem_max = $VAR_UDP_RMEM          # 最大读缓存 (支撑高带宽)
net.core.wmem_max = $VAR_UDP_WMEM          # 最大写缓存 (支撑高带宽)
net.core.optmem_max = 2097152              # Socket辅助内存上限
net.ipv4.udp_mem = $UDP_MEM_SCALE          # UDP 全局内存配额 (动态调节)
net.ipv4.tcp_rmem = 4096 87380 $tcp_rmem_max   # TCP 读缓存动态范围
net.ipv4.tcp_wmem = 4096 65536 $tcp_rmem_max   # TCP 写缓存动态范围

# --- 协议栈深度调优 (Hy2 传输核心) ---
net.ipv4.tcp_congestion_control = $tcp_cca # 拥塞算法 (BBR/Cubic)
net.ipv4.tcp_no_metrics_save = 1           # 实时探测不记忆旧值
net.ipv4.tcp_fastopen = 3                  # 开启 TCP 快开 (降首包延迟)
net.ipv4.tcp_notsent_lowat = 16384         # 限制发送队列 (防延迟抖动)
net.ipv4.tcp_mtu_probing = 1               # MTU自动探测 (防UDP黑洞)
net.ipv4.ip_no_pmtu_disc = 0               # 启用路径MTU探测 (寻找最优包大小)
net.ipv4.tcp_frto = 2                      # 丢包环境重传判断优化
net.ipv4.tcp_slow_start_after_idle = $([ "$rtt_avg" -ge 150 ] && echo "1" || echo "0") # 闲置后慢启动开关
net.ipv4.tcp_limit_output_bytes = $([ "$mem_total" -ge 200 ] && echo "262144" || echo "131072") # 限制TCP连接占用发送队列
net.ipv4.udp_gro_enabled = 1               # UDP 分段聚合 (降CPU负载)
net.ipv4.udp_early_demux = 1               # UDP 早期路由优化
net.ipv4.udp_l4_early_demux = 1            # UDP 四层早期分流

# --- BBRv3 / ECN 联动 ---
net.ipv4.tcp_ecn = 1                       # 开启显式拥塞通知
net.ipv4.tcp_ecn_fallback = 1              # ECN 不兼容时自动回退
$(if [[ "$tcp_cca" == "bbr3" ]]; then echo "net.ipv4.tcp_ecn = 2"; echo "net.ipv4.tcp_reflect_tos = 1"; fi)

# === 四、 连接跟踪与超时管理 (及低内存保护) ===
net.netfilter.nf_conntrack_max = $ct_max   # 连接跟踪上限
net.netfilter.nf_conntrack_udp_timeout = $ct_udp_to           # 缩短无效连接回收
net.netfilter.nf_conntrack_udp_timeout_stream = $ct_stream_to # 优化流连接回收
net.ipv4.tcp_fin_timeout = 20              # 孤儿连接回收时间
net.ipv4.tcp_tw_reuse = 1                  # 端口重用
net.ipv4.tcp_max_orphans = $((mem_total * 1024)) # 最大孤儿连接数限制

$([ "$mem_total" -lt 100 ] && cat <<LOWMEM
# --- 针对 96M 小鸡的极低内存保护策略 ---
net.ipv4.tcp_sack = 0                      # 禁用SACK (省内存)
net.ipv4.tcp_dsack = 0                     # 禁用D-SACK
net.ipv4.tcp_fack = 0                      # 禁用前向确认
net.ipv4.tcp_timestamps = 0                # 禁用时间戳 (省包头开销)
net.ipv4.tcp_moderate_rcvbuf = 0           # 锁定手动缓冲区 (防内核抢占)
net.ipv4.tcp_max_syn_backlog = 2048        # 缩减握手队列
LOWMEM
)
SYSCTL
    # 加载配置（优先 sysctl --system，其次回退）
	if command -v sysctl >/dev/null 2>&1 && sysctl --system >/dev/null 2>&1; then :
	else sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true; fi
}

# ==========================================
# 安装/更新 Sing-box 内核
# ==========================================
install_singbox() {
    # 1. 初始化所有变量：将路径从内存 /tmp 移至磁盘 /var/tmp (内存避震)
    local MODE="${1:-install}" LOCAL_VER="未安装" LATEST_TAG="" DOWNLOAD_SOURCE="GitHub" FILE="" URL="" TD="/var/tmp/sb_build" TF="" dl_ok=false RJ="" best_link="" LINK="" NEW_BIN="" VER="" SBOX_ARCH="${SBOX_ARCH:-amd64}"
    local MODE="${1:-install}" LOCAL_VER="未安装" LATEST_TAG="" DOWNLOAD_SOURCE="GitHub" FILE="" URL="" TD="" TF="" dl_ok=false RJ="" best_link="" LINK="" NEW_BIN="" VER="" SBOX_ARCH="${SBOX_ARCH:-amd64}"
    local curl_try=0 source_try=0
    [ -f /usr/bin/sing-box ] && LOCAL_VER=$(/usr/bin/sing-box version 2>/dev/null | head -n1 | awk '{print $3}')
    

    info "获取 Sing-Box 最新版本信息..."
    RJ=$(curl -sL --connect-timeout 10 --max-time 15 "https://api.github.com/repos/SagerNet/sing-box/releases/latest" 2>/dev/null)
    while [ $curl_try -lt 3 ] && [ -z "$RJ" ]; do
        RJ=$(curl -sL --connect-timeout 10 --max-time 15 "https://api.github.com/repos/SagerNet/sing-box/releases/latest" 2>/dev/null)
        curl_try=$((curl_try + 1))
        [ -z "$RJ" ] && sleep 1
    done
    [ -n "$RJ" ] && LATEST_TAG=$(echo "$RJ" | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"v[0-9.]+"' | head -n1 | cut -d'"' -f4)
    [ -z "$LATEST_TAG" ] && { DOWNLOAD_SOURCE="官方镜像"; LATEST_TAG=$(curl -sL --connect-timeout 10 "https://sing-box.org/" 2>/dev/null | grep -oE 'v1\.[0-9]+\.[0-9]+' | head -n1); }
    [ -z "$LATEST_TAG" ] && { [ "$LOCAL_VER" != "未安装" ] && { warn "远程获取失败，保持 v$LOCAL_VER"; return 0; } || { err "获取版本失败，请检查网络"; exit 1; }; }

    local REMOTE_VER="${LATEST_TAG#v}"
    if [[ "$MODE" == "update" ]]; then
        echo -e "---------------------------------"
        echo -e "当前已装版本: \033[1;33m${LOCAL_VER}\033[0m"
        echo -e "官方最新版本: \033[1;32m${REMOTE_VER}\033[0m (源: $DOWNLOAD_SOURCE)"
        echo -e "当前已装版本: [1;33m${LOCAL_VER}[0m"
        echo -e "官方最新版本: [1;32m${REMOTE_VER}[0m (源: $DOWNLOAD_SOURCE)"
        echo -e "---------------------------------"
        [[ "$LOCAL_VER" == "$REMOTE_VER" ]] && { succ "内核已是最新版本"; return 1; }
        info "发现新版本，开始下载更新..."
    fi

    # 2. 后台并行探测模式
    FILE="sing-box-${REMOTE_VER}-linux-${SBOX_ARCH}.tar.gz"; URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST_TAG}/${FILE}"
    rm -rf "$TD" && mkdir -p "$TD" && TF="$TD/sb.tar.gz"; local LINKS=("$URL" "https://ghproxy.net/$URL" "https://kkgh.tk/$URL" "https://gh.ddlc.top/$URL" "https://gh-proxy.com/$URL")
    FILE="sing-box-${REMOTE_VER}-linux-${SBOX_ARCH}.tar.gz"
    URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST_TAG}/${FILE}"
    TD=$(mktemp -d /var/tmp/sb_build.XXXXXX 2>/dev/null || echo "/var/tmp/sb_build")
    rm -rf "$TD" && mkdir -p "$TD"
    TF="$TD/sb.tar.gz"
    trap 'rm -rf "$TD" >/dev/null 2>&1' EXIT INT TERM

    local LINKS=("$URL" "https://ghproxy.net/$URL" "https://kkgh.tk/$URL" "https://gh.ddlc.top/$URL" "https://gh-proxy.com/$URL")
    info "正在筛选最优下载节点 (并行模式)..."
    for LINK in "${LINKS[@]}"; do (curl -Is --connect-timeout 4 --max-time 6 "$LINK" | grep -q "200 OK" && echo "$LINK" > "$TD/best_node") & done
    wait # 等待所有后台进程
    best_link=$( [ -f "$TD/best_node" ] && head -n1 "$TD/best_node" || echo "${LINKS[0]}" )
    
    for LINK in "${LINKS[@]}"; do
        (curl -Is --connect-timeout 4 --max-time 6 "$LINK" | grep -q "200 OK" && echo "$LINK" > "$TD/best_node") &
    done
    wait
    best_link=$([ -f "$TD/best_node" ] && head -n1 "$TD/best_node" || echo "${LINKS[0]}")

    # 3. 稳健下载逻辑
    info "选定节点: $(echo "$best_link" | cut -d'/' -f3)，启动下载..."
    { curl -fkL -C - --connect-timeout 15 --retry 3 --retry-delay 2 "$best_link" -o "$TF" && [ "$(stat -c%s "$TF" 2>/dev/null || echo 0)" -gt 8000000 ]; } && dl_ok=true || {
    if curl -fkL -C - --connect-timeout 15 --max-time 120 --retry 5 --retry-delay 2 --retry-all-errors "$best_link" -o "$TF"        && [ "$(stat -c%s "$TF" 2>/dev/null || echo 0)" -gt 8000000 ]; then
        dl_ok=true
    else
        warn "首选源体积异常或下载失败，尝试遍历备用源..."
        for LINK in "${LINKS[@]}"; do info "尝试源: $(echo "$LINK" | cut -d'/' -f3)..."; curl -fkL --connect-timeout 10 --max-time 60 "$LINK" -o "$TF" && [ "$(stat -c%s "$TF" 2>/dev/null || echo 0)" -gt 8000000 ] && { dl_ok=true; break; }; done
    }
    [ "$dl_ok" = false ] && { [ "$LOCAL_VER" != "未安装" ] && { warn "所有源失效，保留旧版"; rm -rf "$TD"; return 0; } || { err "下载失败"; exit 1; }; }
        for LINK in "${LINKS[@]}"; do
            info "尝试源: $(echo "$LINK" | cut -d'/' -f3)..."
            source_try=0
            while [ $source_try -lt 2 ]; do
                if curl -fkL -C - --connect-timeout 10 --max-time 90 --retry 2 --retry-delay 1 --retry-all-errors "$LINK" -o "$TF"                    && [ "$(stat -c%s "$TF" 2>/dev/null || echo 0)" -gt 8000000 ]; then
                    dl_ok=true
                    break
                fi
                source_try=$((source_try + 1))
                sleep 1
            done
            [ "$dl_ok" = true ] && break
        done
    fi

    if [ "$dl_ok" = false ]; then
        trap - EXIT INT TERM
        rm -rf "$TD"
        [ "$LOCAL_VER" != "未安装" ] && { warn "所有源失效，保留旧版"; return 0; } || { err "下载失败"; exit 1; }
    fi

    # 4. 优化解压与安装：拒绝自杀式中断 (防 SSH 断开)
    info "正在解压并准备安装内核..."; tar -xf "$TF" -C "$TD" >/dev/null 2>&1 && NEW_BIN=$(find "$TD" -type f -name "sing-box" | head -n1)
    if [ -f "$NEW_BIN" ]; then
        chmod 755 "$NEW_BIN" && cp -f "$NEW_BIN" /usr/bin/sing-box
        pgrep -x sing-box >/dev/null && { info "正在热重启服务以完成更新..."; service_ctrl restart || { service_ctrl stop; sleep 1; service_ctrl start; }; }
        rm -rf "$TD" && VER=$(/usr/bin/sing-box version 2>/dev/null | head -n1 | awk '{print $3}') && succ "内核安装成功: v$VER"
    else rm -rf "$TD" && err "解压校验失败：未找到二进制文件" && return 1; fi
    info "正在解压并准备安装内核..."
    tar -xf "$TF" -C "$TD" >/dev/null 2>&1
    NEW_BIN=$(find "$TD" -type f -name "sing-box" | head -n1)
    if [ ! -f "$NEW_BIN" ]; then
        trap - EXIT INT TERM
        rm -rf "$TD"
        err "解压校验失败：未找到二进制文件"
        return 1
    fi

    chmod 755 "$NEW_BIN"
    [ -f /usr/bin/sing-box ] && cp -f /usr/bin/sing-box /usr/bin/sing-box.bak >/dev/null 2>&1 || true
    if ! cp -f "$NEW_BIN" /usr/bin/sing-box.new || ! mv -f /usr/bin/sing-box.new /usr/bin/sing-box || ! /usr/bin/sing-box version >/dev/null 2>&1; then
        [ -f /usr/bin/sing-box.bak ] && cp -f /usr/bin/sing-box.bak /usr/bin/sing-box >/dev/null 2>&1
        trap - EXIT INT TERM
        rm -rf "$TD"
        err "解压校验失败：未找到二进制文件"
        return 1
    fi

    pgrep -x sing-box >/dev/null && { info "正在热重启服务以完成更新..."; service_ctrl restart || { service_ctrl stop; sleep 1; service_ctrl start; }; }
    trap - EXIT INT TERM
    rm -rf "$TD"
    VER=$(/usr/bin/sing-box version 2>/dev/null | head -n1 | awk '{print $3}')
    succ "内核安装成功: v$VER"
}

# ==========================================
# 配置文件生成
# ==========================================
create_config() {
    local PORT_HY2="${1:-}"
	local cur_bw="${VAR_HY2_BW:-200}"
    mkdir -p /etc/sing-box
    local ds="ipv4_only"; local PSK=""; local SALA_PASS=""
    [ "${IS_V6_OK:-false}" = "true" ] && ds="prefer_ipv4"
	local mem_total=$(probe_memory_total); : ${mem_total:=64}; local timeout="30s"
	[ "$mem_total" -ge 100 ] && timeout="40s"; [ "$mem_total" -ge 200 ] && timeout="50s"; [ "$mem_total" -ge 450 ] && timeout="60s"
    
    # 1. 端口确定逻辑
    if [ -z "$PORT_HY2" ]; then
        if [ -f /etc/sing-box/config.json ]; then PORT_HY2=$(jq -r '.inbounds[0].listen_port' /etc/sing-box/config.json)
        else PORT_HY2=$(printf "\n" | prompt_for_port); fi
    fi
    
    # 2. PSK (密码) 确定逻辑
    [ -f /etc/sing-box/config.json ] && PSK=$(jq -r '.. | objects | select(.type == "hysteria2") | .users[0].password // empty' /etc/sing-box/config.json 2>/dev/null | head -n 1)
    [ -z "$PSK" ] && [ -f /proc/sys/kernel/random/uuid ] && PSK=$(cat /proc/sys/kernel/random/uuid | tr -d '\n')
    [ -z "$PSK" ] && { local s=$(openssl rand -hex 16); PSK="${s:0:8}-${s:8:4}-${s:12:4}-${s:16:4}-${s:20:12}"; }

    # 3. Salamander 混淆密码确定逻辑
    [ -f /etc/sing-box/config.json ] && SALA_PASS=$(jq -r '.. | objects | select(.type == "salamander") | .password // empty' /etc/sing-box/config.json 2>/dev/null | head -n 1)
    [ -z "$SALA_PASS" ] && SALA_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)

    # 4. 写入 Sing-box 配置文件
    cat > "/etc/sing-box/config.json" <<EOF
{
  "log": { "level": "fatal", "timestamp": true },
  "dns": {"servers":[{"address":"8.8.4.4","detour":"direct-out"},{"address":"1.1.1.1","detour":"direct-out"}],"strategy":"$ds","independent_cache":false,"disable_cache":false,"disable_expire":false},
  "inbounds": [{
    "type": "hysteria2",
    "tag": "hy2-in",
    "listen": "::",
    "listen_port": $PORT_HY2,
    "users": [ { "password": "$PSK" } ],
    "ignore_client_bandwidth": false,
    "up_mbps": $cur_bw,
    "down_mbps": $cur_bw,
    "udp_timeout": "$timeout",
    "udp_fragment": true,
    "tls": {"enabled": true, "alpn": ["h3"], "min_version": "1.3", "certificate_path": "/etc/sing-box/certs/fullchain.pem", "key_path": "/etc/sing-box/certs/privkey.pem"},
    "obfs": {"type": "salamander", "password": "$SALA_PASS"},
    "masquerade": "https://${TLS_DOMAIN:-www.microsoft.com}"
  }],
  "outbounds": [{"type": "direct", "tag": "direct-out", "domain_strategy": "$ds"}]
}
EOF
    chmod 600 "/etc/sing-box/config.json"
}

# ==========================================
# 服务配置
# ==========================================
setup_service() {
    local real_c="$CPU_CORE" core_range="" pid=""
    local taskset_bin=$(command -v taskset 2>/dev/null || echo "taskset")
    local ionice_bin=$(command -v ionice 2>/dev/null || echo "")
    local cur_nice="${VAR_SYSTEMD_NICE:--5}"; local io_class="${VAR_SYSTEMD_IOSCHED:-best-effort}"
    local mem_total=$(probe_memory_total); local io_prio=4
    [ "$real_c" -le 1 ] && core_range="0" || core_range="0-$((real_c - 1))"
    [ "$mem_total" -ge 450 ] && [ "$io_class" = "realtime" ] && io_prio=0 || io_prio=4
    [ "$mem_total" -lt 200 ] && io_prio=7 
    local final_nice="$cur_nice"
    info "配置服务 (核心: $real_c | 绑定: $core_range | Nice预设: $cur_nice)..."
    if ! renice "$cur_nice" $$ >/dev/null 2>&1; then
        warn "当前环境禁止高优先级调度，已自动回退至默认权重 (Nice 0)"
        final_nice=0
    fi
    info "正在写入配置并启动服务..."
    if [ "$OS" = "alpine" ]; then
        command -v taskset >/dev/null || apk add --no-cache util-linux >/dev/null 2>&1
        cat > /etc/init.d/sing-box <<EOF
#!/sbin/openrc-run
name="sing-box"
description="Sing-box Service"
supervisor="supervise-daemon"
respawn_delay=10
respawn_max=5
respawn_period=60
[ -f /etc/sing-box/env ] && . /etc/sing-box/env
export GOTRACEBACK=none
command="/usr/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
pidfile="/run/\${RC_SVCNAME}.pid"
supervise_daemon_args="--nicelevel ${final_nice}"
rc_ulimit="-n 1000000"
rc_nice="${final_nice}"
rc_oom_score_adj="-500"
depend() { need net; after firewall; }
start_pre() { /usr/bin/sing-box check -c /etc/sing-box/config.json >/tmp/sb_err.log 2>&1 || { echo "Config check failed:" && cat /tmp/sb_err.log && return 1; }; }
EOF
        chmod +x /etc/init.d/sing-box
        rc-update add sing-box default >/dev/null 2>&1 || true
        sync   # 确保环境文件与服务脚本落盘，防止启动瞬时读取失败
		(rc-service sing-box restart >/dev/null 2>&1 || true) &
    else
        local mem_config=""; local cpu_quota=$((real_c * 100))
        local io_config="IOSchedulingClass=${io_class}"$'\n'"IOSchedulingPriority=${io_prio}"
        [ "$cpu_quota" -lt 100 ] && cpu_quota=100
        [ -n "$SBOX_MEM_HIGH" ] && mem_config="MemoryHigh=$SBOX_MEM_HIGH"$'\n'
        [ -n "$SBOX_MEM_MAX" ] && mem_config+="MemoryMax=$SBOX_MEM_MAX"$'\n'
        local systemd_nice_line="Nice=${final_nice}"
        [ "${final_nice}" -eq 0 ] && systemd_nice_line="# Nice=0 (Environment restricted)"
        cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-box Service
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
StartLimitBurst=3

[Service]
Type=simple
User=root
EnvironmentFile=-/etc/sing-box/env
Environment=GOTRACEBACK=none
ExecStartPre=/usr/bin/sing-box check -c /etc/sing-box/config.json
ExecStart=${taskset_bin} -c ${core_range} /usr/bin/sing-box run -c /etc/sing-box/config.json
${systemd_nice_line}
${io_config}
LimitNOFILE=1000000
LimitMEMLOCK=infinity
${mem_config}CPUQuota=${cpu_quota}%
OOMPolicy=continue
OOMScoreAdjust=-500
Restart=always
RestartSec=10s
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload >/dev/null 2>&1
        systemctl enable sing-box >/dev/null 2>&1 || true
        sync   # 确保环境文件与服务配置落盘
		(systemctl restart sing-box >/dev/null 2>&1 || true) &
    fi
    set +e     # 关闭 set -e，这是防止脚本在 pidof 失败时直接退出的关键核心
    for i in {1..40}; do
        pid=$(pgrep -x "sing-box" 2>/dev/null | head -n 1)
        [ -z "${pid}" ] && pid=$(pgrep -f "sing-box run" | awk '{print $1}' | head -n 1)
        [ -n "${pid}" ] && [ -e "/proc/${pid}" ] && break
        sleep 0.3
    done
    # 异步补课逻辑。在进程确认拉起后，从脚本主体执行一次优化，这样既保证了优化生效，又不会因为优化脚本运行时间长而导致服务启动超时
    ([ -f "$SBOX_CORE" ] && /bin/bash "$SBOX_CORE" --apply-cwnd) >/dev/null 2>&1 &
    if [ -n "$pid" ] && [ -e "/proc/$pid" ]; then
        local ma=$(awk '/^MemAvailable:/{a=$2;f=1} /^MemFree:|Buffers:|Cached:/{s+=$2} END{print (f?a:s)}' /proc/meminfo 2>/dev/null)
        succ "sing-box 启动成功 | 总内存: ${mem_total:-N/A} MB | 可用: $(( ${ma:-0} / 1024 )) MB | 模式: $([[ "$INITCWND_DONE" == "true" ]] && echo "内核" || echo "应用层")"
    else
        err "服务拉起超时，请检查日志："
        [ "$OS" = "alpine" ] && { [ -f /var/log/messages ] && tail -n 10 /var/log/messages || logread | tail -n 10; } || journalctl -u sing-box -n 10 --no-pager 2>/dev/null
        set -e; exit 1
    fi
	set -e
}

# ==========================================
# 信息展示模块
# ==========================================
get_env_data() {
    local CONFIG_FILE="/etc/sing-box/config.json"
    [ ! -f "$CONFIG_FILE" ] && return 1
    local data=$(jq -r '.. | objects | select(.type == "hysteria2") | "\(.users[0].password) \(.listen_port) \(.obfs.password) \(.tls.certificate_path)"' "$CONFIG_FILE" 2>/dev/null | head -n 1)
	read -r RAW_PSK RAW_PORT RAW_SALA CERT_PATH <<< "$data" || true
    RAW_SNI=$(openssl x509 -in "$CERT_PATH" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/.*CN=\([^,]*\).*/\1/' || echo "$TLS_DOMAIN")
    local FP_FILE="/etc/sing-box/certs/cert_fingerprint.txt"
    RAW_FP=$([ -f "$FP_FILE" ] && cat "$FP_FILE" || openssl x509 -in "$CERT_PATH" -noout -sha256 -fingerprint 2>/dev/null | cut -d'=' -f2 | tr -d ': ' | tr '[:upper:]' '[:lower:]')
}

display_links() {
    local LINK_V4="" LINK_V6="" FULL_CLIP="" v4_status="" v6_status=""
    local BASE_PARAM="sni=$RAW_SNI&alpn=h3&insecure=1"
    [ -n "${RAW_FP:-}" ] && BASE_PARAM="${BASE_PARAM}&pinsha256=${RAW_FP}"
    [ -n "${RAW_SALA:-}" ] && BASE_PARAM="${BASE_PARAM}&obfs=salamander&obfs-password=${RAW_SALA}"
	
    _do_probe() {
        [ -z "$1" ] && return
		(nc -z -u -w 1 "$1" "$RAW_PORT" || { sleep 0.3; nc -z -u -w 2 "$1" "$RAW_PORT"; }) >/dev/null 2>&1 && \
        echo -e "\033[1;32m (已连通)\033[0m" || echo -e "\033[1;33m (本地受阻)\033[0m"
    }
    if command -v nc >/dev/null 2>&1; then
        _do_probe "${RAW_IP4:-}" > /tmp/sb_v4 2>&1 & _do_probe "${RAW_IP6:-}" > /tmp/sb_v6 2>&1 & wait
        v4_status=$(cat /tmp/sb_v4 2>/dev/null); v6_status=$(cat /tmp/sb_v6 2>/dev/null)
    fi
    echo -e "\n\033[1;32m[节点信息]\033[0m \033[1;34m>>>\033[0m 运行端口: \033[1;33m${RAW_PORT:-"未知"}\033[0m\n"
	
    [ -n "${RAW_IP4:-}" ] && {
        LINK_V4="hy2://$RAW_PSK@$RAW_IP4:$RAW_PORT/?${BASE_PARAM}#$(hostname)_v4"
        echo -e "\033[1;35m[IPv4节点链接]\033[0m$v4_status\n$LINK_V4\n"
        FULL_CLIP="$LINK_V4"
    }
    [ -n "${RAW_IP6:-}" ] && {
        LINK_V6="hy2://$RAW_PSK@[$RAW_IP6]:$RAW_PORT/?${BASE_PARAM}#$(hostname)_v6"
        echo -e "\033[1;36m[IPv6节点链接]\033[0m$v6_status\n$LINK_V6\n"
        FULL_CLIP="${FULL_CLIP:+$FULL_CLIP\n}$LINK_V6"
    }
    echo -e "\033[1;34m==========================================\033[0m"
    [ -n "${RAW_FP:-}" ] && echo -e "\033[1;32m[安全提示]\033[0m 证书 SHA256 指纹已集成，支持强校验"
    [ -n "$FULL_CLIP" ] && copy_to_clipboard "$FULL_CLIP"
}

display_system_status() {
    local VER_INFO=$(/usr/bin/sing-box version 2>/dev/null | head -n1 | sed 's/version /v/')
    local ROUTE_DEF=$(ip route show default | head -n1)
    local CWND_VAL=$(echo "$ROUTE_DEF" | awk -F'initcwnd ' '{if($2){split($2,a," ");print a[1]}else{print "10"}}')
    local CWND_LBL=$(echo "$ROUTE_DEF" | grep -q "initcwnd" && echo "(已优化)" || echo "(默认)")
    local SBOX_PID=$(pgrep sing-box | head -n1)
    local NI_VAL="(未探测)"; local NI_LBL=""
    if [ -n "$SBOX_PID" ] && [ -f "/proc/$SBOX_PID/stat" ]; then
        NI_VAL=$(cat "/proc/$SBOX_PID/stat" | awk '{print $19}')
        [ "$NI_VAL" -lt 0 ] && NI_LBL="(进程优先)" || { [ "$NI_VAL" -gt 0 ] && NI_LBL="(低优先级)" || NI_LBL="(默认)"; }
    fi
    local current_cca=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
    case "$current_cca" in bbr3) bbr_display="BBRv3 (极致响应)" ;; bbr2) bbr_display="BBRv2 (平衡加速)" ;; bbr) bbr_display="BBRv1 (标准加速)" ;; *) bbr_display="$current_cca (非标准)" ;; esac

    echo -e "系统版本: \033[1;33m$OS_DISPLAY\033[0m"
    echo -e "内核信息: \033[1;33m$VER_INFO\033[0m"
    echo -e "进程权重: \033[1;33mNice $NI_VAL $NI_LBL\033[0m"
    echo -e "Initcwnd: \033[1;33m$CWND_VAL $CWND_LBL\033[0m"
    echo -e "拥塞控制: \033[1;33m$bbr_display\033[0m"
    echo -e "优化级别: \033[1;32m${SBOX_OPTIMIZE_LEVEL:-未检测}\033[0m"
    echo -e "伪装SNI:  \033[1;33m${RAW_SNI:-未检测}\033[0m"
    echo -e "IPv4地址: \033[1;33m${RAW_IP4:-无}\033[0m"
    echo -e "IPv6地址: \033[1;33m${RAW_IP6:-无}\033[0m"
}

# ==========================================
# 管理脚本生成
# ==========================================
create_sb_tool() {
    mkdir -p /etc/sing-box
    local FINAL_SALA=$(jq -r '.inbounds[0].obfs.password // empty' /etc/sing-box/config.json 2>/dev/null || echo "")
    local CORE_TMP=$(mktemp) || CORE_TMP="/tmp/core_script_$$.sh"
    # 写入固化变量
    cat > "$CORE_TMP" <<EOF
#!/usr/bin/env bash
set -uo pipefail
OS='$OS'
SBOX_ARCH='$SBOX_ARCH'
CPU_CORE='$CPU_CORE'
SBOX_CORE='$SBOX_CORE'
VAR_HY2_BW='${VAR_HY2_BW:-200}'
SBOX_GOLIMIT='$SBOX_GOLIMIT'
SBOX_GOGC='${SBOX_GOGC:-100}'
SBOX_MEM_MAX='$SBOX_MEM_MAX'
SBOX_MEM_HIGH='${SBOX_MEM_HIGH:-}'
SBOX_OPTIMIZE_LEVEL='$SBOX_OPTIMIZE_LEVEL'
INITCWND_DONE='${INITCWND_DONE:-false}'
VAR_SYSTEMD_NICE='${VAR_SYSTEMD_NICE:--5}'
VAR_SYSTEMD_IOSCHED='$VAR_SYSTEMD_IOSCHED'
OS_DISPLAY='$OS_DISPLAY'
TLS_DOMAIN='$TLS_DOMAIN'
RAW_SNI='${RAW_SNI:-$TLS_DOMAIN}'
RAW_SALA='$FINAL_SALA'
RAW_IP4='${RAW_IP4:-}'
RAW_IP6='${RAW_IP6:-}'
IS_V6_OK='${IS_V6_OK:-false}'
EOF

    # 导出函数
    local funcs=(probe_network_rtt probe_memory_total apply_initcwnd_optimization prompt_for_port
        get_cpu_core get_env_data display_links display_system_status detect_os copy_to_clipboard
        optimize_system install_singbox create_config setup_service apply_firewall service_ctrl info err warn succ
        apply_userspace_adaptive_profile apply_nic_core_boost
        setup_zrm_swap safe_rtt generate_cert)

    for f in "${funcs[@]}"; do
        if declare -f "$f" >/dev/null 2>&1; then declare -f "$f" >> "$CORE_TMP"; echo "" >> "$CORE_TMP"; fi
    done

    cat >> "$CORE_TMP" <<'EOF'
detect_os; set +e
apply_firewall
if [[ "${1:-}" == "--detect-only" ]]; then :
elif [[ "${1:-}" == "--show-only" ]]; then
    get_env_data; echo -e "\n\033[1;34m==========================================\033[0m"
    display_system_status; display_links
elif [[ "${1:-}" == "--reset-port" ]]; then
    create_config "$2"; service_ctrl restart; get_env_data; display_links
elif [[ "${1:-}" == "--update-kernel" ]]; then
    if install_singbox "update"; then
        service_ctrl restart; succ "内核已更新并应用防火墙规则"
    fi
elif [[ "${1:-}" == "--apply-cwnd" ]]; then
    apply_userspace_adaptive_profile >/dev/null 2>&1 || true
    apply_initcwnd_optimization "true" || true; apply_firewall
fi
EOF
    mv "$CORE_TMP" "$SBOX_CORE"
    chmod 700 "$SBOX_CORE"

    # 生成交互管理脚本 /usr/local/bin/sb
    local SB_PATH="/usr/local/bin/sb"
    cat > "$SB_PATH" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
SBOX_CORE="/etc/sing-box/core_script.sh"
if [ ! -f "$SBOX_CORE" ]; then echo "核心文件丢失"; exit 1; fi
[[ $# -gt 0 ]] && { /bin/bash "$SBOX_CORE" "$@"; exit 0; }
source "$SBOX_CORE" --detect-only

while true; do
    echo "========================" 
    echo " Sing-box HY2 管理 (sb)"
    echo "-------------------------------------------------"
    echo " Level: ${SBOX_OPTIMIZE_LEVEL:-未知} | Plan: $([[ "$INITCWND_DONE" == "true" ]] && echo "Initcwnd 15" || echo "应用层补偿")"
    echo "-------------------------------------------------"
    echo "1. 查看信息    2. 修改配置    3. 重置端口"
    echo "4. 更新内核    5. 重启服务    6. 卸载脚本"
    echo "0. 退出"
    echo ""  
    read -r -p "请选择 [0-6]: " opt
    opt=$(echo "$opt" | xargs echo -n 2>/dev/null || echo "$opt")
    if [[ -z "$opt" ]] || [[ ! "$opt" =~ ^[0-6]$ ]]; then
        echo -e "\033[1;31m输入有误 [$opt]，请重新输入\033[0m"; sleep 1; continue
    fi
    case "$opt" in
        1) source "$SBOX_CORE" --show-only; read -r -p $'\n按回车键返回菜单...' ;;
        2) f="/etc/sing-box/config.json"; old=$(md5sum $f 2>/dev/null)
            vi $f; if [ "$old" != "$(md5sum $f 2>/dev/null)" ]; then
                service_ctrl restart && succ "配置已更新，网络画像与防火墙已同步刷新"
            else info "配置未作变更"; fi
            read -r -p $'\n按回车键返回菜单...' ;;
        3) source "$SBOX_CORE" --reset-port "$(prompt_for_port)"; read -r -p $'\n按回车键返回菜单...' ;;
        4) source "$SBOX_CORE" --update-kernel; read -r -p $'\n按回车键返回菜单...' ;;
        5) service_ctrl restart && info "系统服务和优化参数已重载"; read -r -p $'\n按回车键返回菜单...' ;;
        6) read -r -p "是否确定卸载？(默认N) [Y/N]: " cf
           if [ "${cf:-n}" = "y" ] || [ "${cf:-n}" = "Y" ]; then
               info "正在执行深度卸载..."
               systemctl stop sing-box zram-swap 2>/dev/null; rc-service sing-box stop 2>/dev/null
               swapoff -a 2>/dev/null
               [ -w /sys/block/zram0/reset ] && echo 1 > /sys/block/zram0/reset 2>/dev/null
               rm -rf /etc/sing-box /usr/bin/sing-box /usr/local/bin/{sb,SB} \
                      /etc/systemd/system/{sing-box,zram-swap}.service /etc/init.d/{sing-box,zram-swap} \
                      /etc/sysctl.d/99-sing-box.conf /tmp/sb_* ~/.acme.sh /swapfile
               sed -i '/swapfile/d' /etc/fstab; crontab -l 2>/dev/null | grep -v "acme.sh" | crontab - 2>/dev/null
               printf "net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\nvm.swappiness=60\n" > /etc/sysctl.conf
               sysctl -p >/dev/null 2>&1; systemctl daemon-reload 2>/dev/null; succ "深度卸载完成"; exit 0
           else info "卸载操作已取消"; read -r -p "按回车键返回菜单..." ; fi ;;
        0) exit 0 ;;
    esac
done
EOF
	chmod +x "$SB_PATH"
    ln -sf "$SB_PATH" "/usr/local/bin/SB" 2>/dev/null || true
}

# ==========================================
# 主运行逻辑
# ==========================================
detect_os
[ "$(id -u)" != "0" ] && err "请使用 root 运行" && exit 1
install_dependencies
CPU_CORE=$(get_cpu_core)
export CPU_CORE
get_network_info
echo -e "-----------------------------------------------"
USER_PORT=$(prompt_for_port)
optimize_system
install_singbox "install"
generate_cert
create_config "$USER_PORT"
create_sb_tool
setup_service
get_env_data
echo -e "\n\033[1;34m==========================================\033[0m"
display_system_status
echo -e "\033[1;34m------------------------------------------\033[0m"
display_links
info "脚本部署完毕，输入 'sb' 管理"
