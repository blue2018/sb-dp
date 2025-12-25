#!/usr/bin/env bash
set -euo pipefail

# -----------------------
# 预声明变量
SBOX_ARCH=""
SBOX_VER="1.12.14" 

# TLS 指纹随机池
TLS_DOMAIN_POOL=(
  "www.bing.com" "www.qq.com" "www.aliyun.com" "www.baidu.com"
  "www.jd.com" "www.taobao.com" "www.mi.com" "www.meituan.com"
  "www.zhihu.com" "www.bilibili.com"
)
pick_tls_domain() {
  echo "${TLS_DOMAIN_POOL[$RANDOM % ${#TLS_DOMAIN_POOL[@]}]}"
}
TLS_DOMAIN="$(pick_tls_domain)"

# -----------------------
# 彩色输出函数
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }

# -----------------------
# 检测系统类型
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        ID="${ID:-}"
        ID_LIKE="${ID_LIKE:-}"
    else
        ID=""
        ID_LIKE=""
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
        armv6l)    SBOX_ARCH="armv6" ;;
        i386|i686) SBOX_ARCH="386" ;;
        *) err "不支持的 CPU 架构: $ARCH"; exit 1 ;;
    esac
}

detect_os
info "检测到系统: $OS ($ARCH)"

# -----------------------
# 检查 root 权限
check_root() {
    if [ "$(id -u)" != "0" ]; then
        err "此脚本需要 root 权限"
        exit 1
    fi
}
check_root

# -----------------------
# 更新系统并安装依赖
install_deps() {
    info "同步系统软件包并安装依赖..."
    case "$OS" in
        alpine)
            apk update && apk add --no-cache bash curl ca-certificates openssl openrc jq
            ;;
        debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y && apt-get install -y curl ca-certificates openssl jq
            ;;
        redhat)
            yum install -y curl ca-certificates openssl jq
            ;;
    esac
}
install_deps

# -----------------------
# 核心优化：系统内核参数 (针对 64MB 极限收缩)
optimize_system() {
    info "优化系统内核参数 (64MB 适配)..."
    [ -f /etc/sysctl.conf ] && cp /etc/sysctl.conf /etc/sysctl.conf.bak
    
    cat > /etc/sysctl.conf <<'SYSCTL'
# 极限收缩 UDP 缓存，防止内存溢出
net.core.rmem_max = 2097152
net.core.wmem_max = 2097152
net.ipv4.udp_mem = 4096 8192 16384
net.ipv4.udp_rmem_min = 4096
net.ipv4.udp_wmem_min = 4096
net.core.netdev_max_backlog = 500
net.core.somaxconn = 256
net.core.default_qdisc = fq_codel
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_max_orphan_distray = 1024
SYSCTL
    sysctl -p >/dev/null 2>&1 || true
}
optimize_system

# -----------------------
# 工具函数
rand_port() { shuf -i 10000-60000 -n 1 2>/dev/null || echo $((RANDOM % 50001 + 10000)); }
rand_uuid() { cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16; }

SERVER_NAME=$(hostname 2>/dev/null || echo "server")
echo "${SERVER_NAME}" > /root/node_names.txt
suffix="hy2-${SERVER_NAME}"

# -----------------------
# 安装/下载 sing-box 函数 (供主脚本和 sb 调用)
download_singbox() {
    local VERSION=$1
    local TARGET_DIR=$2
    info "正在下载 sing-box v${VERSION}..."
    local URL="https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-linux-${SBOX_ARCH}.tar.gz"
    local TMP_FILE=$(mktemp)
    curl -fL "$URL" -o "$TMP_FILE" || return 1
    tar -xf "$TMP_FILE" -C "$TARGET_DIR"
    rm -f "$TMP_FILE"
}

# -----------------------
# 生成 ECC 证书
generate_cert() {
    info "生成 ECC 证书..."
    mkdir -p /etc/sing-box/certs
    if [ ! -f /etc/sing-box/certs/fullchain.pem ]; then
        openssl ecparam -genkey -name prime256v1 -out /etc/sing-box/certs/privkey.pem
        openssl req -new -x509 -days 3650 -key /etc/sing-box/certs/privkey.pem -out /etc/sing-box/certs/fullchain.pem -subj "/CN=$TLS_DOMAIN"
    fi
}
generate_cert

# -----------------------
# 初始配置生成
info "=== 配置 Hysteria2 (HY2) ==="
read -p "请输入 HY2 端口 (留空随机): " USER_PORT
PORT_HY2="${USER_PORT:-$(rand_port)}"
PSK_HY2=$(rand_uuid)

create_config() {
    mkdir -p /etc/sing-box
    cat > "/etc/sing-box/config.json" <<EOF
{
  "log": { "level": "warn", "timestamp": true },
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "::",
      "listen_port": $PORT_HY2,
      "users": [ { "password": "$PSK_HY2" } ],
      "ignore_client_bandwidth": true,
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": "/etc/sing-box/certs/fullchain.pem",
        "key_path": "/etc/sing-box/certs/privkey.pem"
      }
    }
  ],
  "outbounds": [ { "type": "direct", "tag": "direct-out" } ]
}
EOF
}
create_config

# -----------------------
# 服务安装
setup_service() {
    if [ "$OS" = "alpine" ]; then
        cat > /etc/init.d/sing-box <<'EOF'
#!/sbin/openrc-run
name="sing-box"
export GOGC=30
export GOMEMLIMIT=45MiB
command="/usr/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
pidfile="/run/${RC_SVCNAME}.pid"
EOF
        chmod +x /etc/init.d/sing-box
        rc-update add sing-box default
        rc-service sing-box restart
    else
        cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-box Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/sing-box
Environment=GOGC=30
Environment=GOMEMLIMIT=45MiB
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=5s
MemoryMax=55M
MemorySwapMax=0
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable sing-box --now
    fi
}

# -----------------------
# 安装主程序
info "初次安装主程序..."
TMP_D=$(mktemp -d)
download_singbox "$SBOX_VER" "$TMP_D"
install -m 755 "$TMP_D"/sing-box-*/sing-box /usr/bin/sing-box
rm -rf "$TMP_D"
setup_service

# -----------------------
# 创建 sb 管理面板 (补全完整 action_update)
SB_PATH="/usr/local/bin/sb"
cat > "$SB_PATH" <<EOF
#!/usr/bin/env bash
set -euo pipefail

info() { echo -e "\033[1;34m[INFO]\033[0m \$*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m \$*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m \$*" >&2; }

$DETECT_OS_FUNC

service_ctrl() {
    detect_os
    if [ "\$OS" = "alpine" ]; then
        rc-service sing-box \$1
    else
        systemctl \$1 sing-box
    fi
}

action_update() {
    info "正在检查新版本..."
    REMOTE_TAG=\$(curl -fsSL "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r '.tag_name' | sed 's/^v//')
    LOCAL_VER=\$(sing-box version | head -n1 | awk '{print \$3}' | sed 's/^v//')
    
    if [ "\$REMOTE_TAG" = "\$LOCAL_VER" ]; then
        info "当前已是最新版本 (v\$LOCAL_VER)"
        return
    fi
    
    info "发现新版本 v\$REMOTE_TAG (当前 v\$LOCAL_VER)，准备更新..."
    TMP_U=\$(mktemp -d)
    # 下载函数
    local URL="https://github.com/SagerNet/sing-box/releases/download/v\${REMOTE_TAG}/sing-box-\${REMOTE_TAG}-linux-$SBOX_ARCH.tar.gz"
    if curl -fL "\$URL" -o "\$TMP_U/sb.tar.gz"; then
        tar -xf "\$TMP_U/sb.tar.gz" -C "\$TMP_U"
        # 预校验
        if "\$TMP_U"/sing-box-*/sing-box check -c /etc/sing-box/config.json; then
            info "配置文件校验通过，正在替换并重启..."
            service_ctrl stop
            install -m 755 "\$TMP_U"/sing-box-*/sing-box /usr/bin/sing-box
            service_ctrl start
            info "更新完成！"
        else
            err "校验失败：新版本与旧配置不兼容，更新已取消。"
        fi
    else
        err "下载失败。"
    fi
    rm -rf "\$TMP_U"
}

# 菜单循环
while true; do
    echo "=========================="
    echo " Sing-box HY2 管理面板 (64M 优化版)"
    echo "=========================="
    echo "1) 查看链接   2) 编辑配置   3) 重启服务"
    echo "4) 停止服务   5) 启动服务   6) 状态/日志"
    echo "7) 更新SingBox   8) 卸载脚本   0) 退出"
    echo "=========================="
    read -p "选择: " opt
    case "\$opt" in
        1) 
           PSK=\$(jq -r '.inbounds[0].users[0].password' /etc/sing-box/config.json)
           PORT=\$(jq -r '.inbounds[0].listen_port' /etc/sing-box/config.json)
           IP=\$(curl -s https://api.ipify.org)
           echo "hy2://\$PSK@\$IP:\$PORT/?sni=$TLS_DOMAIN&alpn=h3&insecure=1#hy2-\$(hostname)" ;;
        2) vi /etc/sing-box/config.json && service_ctrl restart ;;
        3) service_ctrl restart ;;
        4) service_ctrl stop ;;
        5) service_ctrl start ;;
        6) detect_os
           if [ "\$OS" = "alpine" ]; then rc-service sing-box status; tail -n 20 /var/log/sing-box.err || true
           else systemctl status sing-box --no-pager; journalctl -u sing-box -n 20 --no-pager; fi ;;
        7) action_update ;;
        8) service_ctrl stop; rm -rf /etc/sing-box /usr/bin/sing-box /usr/local/bin/sb; echo "卸载完成"; exit 0 ;;
        0) exit 0 ;;
    esac
done
EOF

chmod +x "$SB_PATH"
info "部署成功！输入 'sb' 管理。"
