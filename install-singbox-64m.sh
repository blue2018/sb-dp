#!/usr/bin/env bash
set -euo pipefail

# 变量声明与环境准备
SBOX_ARCH=""
OS_DISPLAY=""
SBOX_CORE="/etc/sing-box/core_script.sh"

# TLS 域名随机池 (针对中国大陆环境优化，避免跨区伪装风险)
TLS_DOMAIN_POOL=(
  "www.bing.com"               # 推荐：全球 IP 分布，合法性高
  "www.microsoft.com"          # 推荐：系统更新流量，极具迷惑性
  "download.windowsupdate.com" # 推荐：大流量 UDP 伪装的首选
  "www.icloud.com"             # 推荐：苹果用户常态化出境流量
  "gateway.icloud.com"         # 推荐：iCloud 同步流量
  "cdn.staticfile.org"         # 推荐：国内知名的开源库加速，常去境外取回数据
)
pick_tls_domain() { echo "${TLS_DOMAIN_POOL[$RANDOM % ${#TLS_DOMAIN_POOL[@]}]}"; }
TLS_DOMAIN="$(pick_tls_domain)"


# 彩色输出与工具函数
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }
succ() { echo -e "\033[1;32m[OK]\033[0m $*"; }


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

    if echo "$ID $ID_LIKE" | grep -qi "alpine"; then
        OS="alpine"
    elif echo "$ID $ID_LIKE" | grep -Ei "debian|ubuntu" >/dev/null; then
        OS="debian"
    elif echo "$ID $ID_LIKE" | grep -Ei "centos|rhel|fedora" >/dev/null; then
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


# 安装/更新 Sing-box 内核
install_singbox() {
    local MODE="${1:-install}"
    info "正在连接 GitHub API 获取版本信息..."
    
    local LATEST_TAG=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)
    if [ -z "$LATEST_TAG" ] || [ "$LATEST_TAG" == "null" ]; then
        err "获取版本失败"
        exit 1
    fi
    local REMOTE_VER="${LATEST_TAG#v}"
    
    # 更新模式下的对比逻辑 (第4项功能)
    if [[ "$MODE" == "update" ]]; then
        local LOCAL_VER="未安装"
        if [ -f /usr/bin/sing-box ]; then
            LOCAL_VER=$(/usr/bin/sing-box version | head -n1 | awk '{print $3}')
        fi

        echo -e "---------------------------------"
        echo -e "当前已安装版本: \033[1;33m${LOCAL_VER}\033[0m"
        echo -e "Github最新版本: \033[1;32m${REMOTE_VER}\033[0m"
        echo -e "---------------------------------"

        if [[ "$LOCAL_VER" == "$REMOTE_VER" ]]; then
            succ "内核已是最新版本，无需更新。"
            return 0
        fi
        info "发现新版本，开始下载更新..."
    fi
    
    local URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST_TAG}/sing-box-${REMOTE_VER}-linux-${SBOX_ARCH}.tar.gz"
    local TMP_D=$(mktemp -d)
    
    if curl -fL --retry 3 "$URL" -o "$TMP_D/sb.tar.gz"; then
        tar -xf "$TMP_D/sb.tar.gz" -C "$TMP_D"
        # 停止旧服务
        if pgrep sing-box >/dev/null; then 
            systemctl stop sing-box 2>/dev/null || rc-service sing-box stop 2>/dev/null || true
        fi
        install -m 755 "$TMP_D"/sing-box-*/sing-box /usr/bin/sing-box
        rm -rf "$TMP_D"
        succ "内核部署成功: $(/usr/bin/sing-box version | head -n1)"
    else
        rm -rf "$TMP_D"
        err "下载失败"
        exit 1
    fi
}


# 生成证书
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


# 创建配置文件 (支持端口重置)
create_config() {
    local PORT_HY2="${1:-}"
    mkdir -p /etc/sing-box
    
    # 逻辑：如果没传入端口，尝试读取旧端口，读不到则随机
    if [ -z "$PORT_HY2" ]; then
        if [ -f /etc/sing-box/config.json ]; then
            PORT_HY2=$(jq -r '.inbounds[0].listen_port' /etc/sing-box/config.json)
        else
            PORT_HY2="$((RANDOM % 50000 + 10000))"
        fi
    fi

    local PSK=$([ -f /etc/sing-box/config.json ] && jq -r '.inbounds[0].users[0].password' /etc/sing-box/config.json || openssl rand -hex 16)
    
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
}


# 系统服务启动管理
setup_service() {
    info "配置系统服务..."
    if [ "$OS" = "alpine" ]; then
        cat > /etc/init.d/sing-box <<'EOF'
#!/sbin/openrc-run
name="sing-box"
export GOGC=50
export GOMEMLIMIT=42MiB
command="/usr/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
pidfile="/run/${RC_SVCNAME}.pid"
EOF
        chmod +x /etc/init.d/sing-box
        rc-update add sing-box default && rc-service sing-box restart
    else
        cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-box Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/sing-box
Environment=GOGC=50
Environment=GOMEMLIMIT=42MiB
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
MemoryMax=55M

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload && systemctl enable sing-box --now
    fi
}


# 展示链接信息
show_info() {
    local IP=$(curl -s --max-time 5 https://api.ipify.org || echo "YOUR_IP")
    local CONFIG="/etc/sing-box/config.json"
    if [ ! -f "$CONFIG" ]; then err "配置未找到"; return; fi
    
    local PSK=$(jq -r '.inbounds[0].users[0].password' "$CONFIG")
    local PORT=$(jq -r '.inbounds[0].listen_port' "$CONFIG")
    local SNI=$(openssl x509 -in /etc/sing-box/certs/fullchain.pem -noout -subject -nameopt RFC2253 | sed 's/.*CN=\([^,]*\).*/\1/' || echo "unknown")
    
    local LINK="hy2://$PSK@$IP:$PORT/?sni=$SNI&alpn=h3&insecure=1#$(hostname)"
    
    echo -e "\n\033[1;34m==========================================\033[0m"
    echo -e "\033[1;32m$LINK\033[0m"
    echo -e "\033[1;34m==========================================\033[0m\n"
}


# 创建 sb 管理面板
create_sb_tool() {
    # [核心修复] 解决 cp bash 报错：如果是管道运行，则从 URL 备份
    mkdir -p /etc/sing-box
    if [ -f "$0" ] && grep -q "install_singbox" "$0"; then
        cp -f "$0" "$SBOX_CORE"
    else
        curl -fsSL https://github.com/blue2018/sb-dp/raw/refs/heads/main/install-singbox-64m.sh -o "$SBOX_CORE"
    fi
    chmod +x "$SBOX_CORE"

    local SB_BIN="/usr/local/bin/sb"
    cat > "$SB_BIN" <<'EOF'
#!/usr/bin/env bash
CORE="/etc/sing-box/core_script.sh"
[ ! -f "$CORE" ] && echo "核心脚本丢失" && exit 1

# 初始化环境
source "$CORE" --detect-only

service_ctrl() {
    if [ -f /etc/init.d/sing-box ]; then rc-service sing-box $1
    else systemctl $1 sing-box; fi
}

while true; do
    echo "--------------------------"
    echo " Sing-box 管理面板 (sb)"
    echo "--------------------------"
    echo "1) 查看链接   2) 编辑配置"
    echo "3) 重置端口   4) 更新内核"
    echo "5) 重启服务   6) 查看日志"
    echo "7) 卸载程序   0) 退出"
    echo "--------------------------"
    read -p "选择 [0-7]: " opt
    case "$opt" in
        1) source "$CORE" --show-only ;;
        2) vi /etc/sing-box/config.json && service_ctrl restart ;;
        3) read -p "新端口: " p; source "$CORE" --reset-port "$p" ;;
        4) source "$CORE" --update-kernel ;;
        5) service_ctrl restart && echo "已重启" ;;
        6) 
           if [ -f /etc/init.d/sing-box ]; then tail -n 50 /var/log/messages | grep sing-box
           else journalctl -u sing-box -n 50 --no-pager; fi ;;
        7) 
           service_ctrl stop
           rm -rf /etc/sing-box /usr/bin/sing-box /usr/local/bin/sb /usr/local/bin/SB
           echo "已彻底卸载"; exit 0 ;;
        0) exit 0 ;;
        *) echo "输入无效" ;;
    esac
done
EOF
    chmod +x "$SB_BIN"
    ln -sf "$SB_BIN" "/usr/local/bin/SB"
}


# --- 主逻辑入口 ---
if [[ "${1:-}" == "--detect-only" ]]; then
    detect_os
elif [[ "${1:-}" == "--show-only" ]]; then
    show_info
elif [[ "${1:-}" == "--reset-port" ]]; then
    detect_os && create_config "$2" && setup_service && show_info
elif [[ "${1:-}" == "--update-kernel" ]]; then
    detect_os && install_singbox "update" && setup_service
else
    # 首次安装
    detect_os
    info "正在安装依赖..."
    [ "$OS" = "alpine" ] && apk add --no-cache bash curl jq openssl openrc
    [ "$OS" = "debian" ] && apt-get update && apt-get install -y curl jq openssl
    
    install_singbox "install"
    generate_cert
    create_config ""
    setup_service
    create_sb_tool
    show_info
    succ "安装完成，输入 sb 管理。"
fi
