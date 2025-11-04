#!/usr/bin/env bash
set -euo pipefail

info(){ echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn(){ echo -e "\033[1;33m[WARN]\033[0m $*"; }
err(){ echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }

# -----------------------
# detect OS / arch
detect_env(){
    OS="unknown"
    OS_ID=""
    OS_LIKE=""
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID:-}"
        OS_LIKE="${ID_LIKE:-}"
    fi

    case "$OS_ID" in
        alpine) OS="alpine" ;;
        debian|ubuntu) OS="debian" ;;
        centos|rhel|rocky|almalinux) OS="centos" ;;
        *) 
            if echo "$OS_LIKE" | grep -Ei "debian" >/dev/null 2>&1; then
                OS="debian"
            elif echo "$OS_LIKE" | grep -Ei "rhel|fedora|centos" >/dev/null 2>&1; then
                OS="centos"
            fi
            ;;
    esac

    # arch map
    UNAME_M="$(uname -m)"
    case "$UNAME_M" in
        x86_64|amd64) BOX_ARCH="amd64" ;;
        aarch64|arm64) BOX_ARCH="arm64" ;;
        *) err "不支持的架构: $UNAME_M"; exit 1 ;;
    esac

    info "检测到系统: ${OS:-unknown}, 架构: $BOX_ARCH"
}

# -----------------------
# prompt port / password
prompt_user(){
    read -p "请输入端口（留空则随机 10000-60000）: " USER_PORT
    if [ -z "$USER_PORT" ]; then
        PORT=$(shuf -i 10000-60000 -n 1)
        info "使用随机端口: $PORT"
    else
        if ! [[ "$USER_PORT" =~ ^[0-9]+$ ]] || [ "$USER_PORT" -lt 1 ] || [ "$USER_PORT" -gt 65535 ]; then
            err "端口必须为 1-65535 的数字"
            exit 1
        fi
        PORT="$USER_PORT"
    fi

    read -p "请输入密码（留空则自动生成符合 SS2022 的 Base64 PSK）: " USER_PWD
}

# -----------------------
# install packages
install_deps(){
    info "安装/检查依赖（curl, ca-certificates, tar, gzip, openssl, bash）"
    case "$OS" in
        alpine)
            apk add --no-cache curl ca-certificates tar gzip openssl bash coreutils
            ;;
        debian)
            apt-get update -y
            DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates tar gzip openssl bash jq coreutils
            ;;
        centos)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y curl ca-certificates tar gzip openssl bash jq coreutils
            else
                yum install -y curl ca-certificates tar gzip openssl bash jq coreutils
            fi
            ;;
        *)
            warn "未知发行版，尝试安装常用工具（请按需手动安装）"
            ;;
    esac
}

# -----------------------
# download & install sing-box
install_singbox(){
    info "准备安装 sing-box（二进制）"

    # get latest tag (GitHub API)
    # We'll try to query releases API; if that fails, user can set SINGBOX_VERSION env var
    SINGBOX_VERSION="${SINGBOX_VERSION:-}"
    if [ -z "$SINGBOX_VERSION" ]; then
        info "查询最新版本..."
        SINGBOX_VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest \
            | awk -F'"' '/"tag_name":/ {print $4; exit}')
    fi
    if [ -z "$SINGBOX_VERSION" ]; then
        err "无法获取 sing-box 最新版本，请设置环境变量 SINGBOX_VERSION，比如 SINGBOX_VERSION=v1.12.3"
        exit 1
    fi
    info "将安装 sing-box $SINGBOX_VERSION"

    TMPDIR="$(mktemp -d)"
    trap 'rm -rf "$TMPDIR"' EXIT

    # construct download URL candidates
    # for alpine -> prefer musl artifact: sing-box-<tag>-linux-<arch>-musl.tar.gz
    # for other -> prefer glibc artifact: sing-box-<tag>-linux-<arch>.tar.gz
    if [ "$OS" = "alpine" ]; then
        FILE="sing-box-${SINGBOX_VERSION}-linux-${BOX_ARCH}-musl.tar.gz"
    else
        FILE="sing-box-${SINGBOX_VERSION}-linux-${BOX_ARCH}.tar.gz"
    fi

    URL="https://github.com/SagerNet/sing-box/releases/download/${SINGBOX_VERSION}/${FILE}"

    info "下载 $URL"
    if ! curl -fSL "$URL" -o "$TMPDIR/singbox.tar.gz"; then
        warn "第一次下载失败，尝试补充后缀或 musl/glibc 备选"
        # try alternative names
        if [ "$OS" = "alpine" ]; then
            ALT="sing-box-${SINGBOX_VERSION}-linux-${BOX_ARCH}.tar.gz"
        else
            ALT="sing-box-${SINGBOX_VERSION}-linux-${BOX_ARCH}-musl.tar.gz"
        fi
        ALTURL="https://github.com/SagerNet/sing-box/releases/download/${SINGBOX_VERSION}/${ALT}"
        info "尝试 $ALTURL"
        curl -fSL "$ALTURL" -o "$TMPDIR/singbox.tar.gz" || {
            err "下载 sing-box 二进制失败，请检查网络或指定 SINGBOX_VERSION 环境变量"
            exit 1
        }
    fi

    tar -xzf "$TMPDIR/singbox.tar.gz" -C "$TMPDIR"
    # find sing-box binary directory
    SB_DIR=$(find "$TMPDIR" -maxdepth 2 -type f -name "sing-box" -printf '%h\n' | head -n1 || true)
    if [ -z "$SB_DIR" ]; then
        # maybe binary is at root of tar
        if [ -f "$TMPDIR/sing-box" ]; then
            SB_DIR="$TMPDIR"
        else
            err "解压后未找到 sing-box 可执行文件"
            exit 1
        fi
    fi

    info "安装 sing-box 到 /usr/bin/sing-box"
    install -m 0755 "$SB_DIR/sing-box" /usr/bin/sing-box
    if [ ! -x /usr/bin/sing-box ]; then
        err "安装失败：/usr/bin/sing-box 不存在或不可执行"
        exit 1
    fi

    info "sing-box 已安装：$(/usr/bin/sing-box --version 2>&1 | head -n1 || true)"
}

# -----------------------
# generate PSK
generate_psk(){
    KEY_BYTES=16
    METHOD="2022-blake3-aes-128-gcm"

    if [ -n "${USER_PWD:-}" ]; then
        PSK="$USER_PWD"
        info "使用你输入的密码，请确保为 Base64（或符合协议的字符串）"
    else
        PSK=""
        if command -v sing-box >/dev/null 2>&1; then
            PSK="$(sing-box generate rand --base64 "$KEY_BYTES" 2>/dev/null || true)"
        fi
        if [ -z "$PSK" ] && command -v openssl >/dev/null 2>&1; then
            PSK="$(openssl rand -base64 "$KEY_BYTES" | tr -d '\n')"
        fi
        if [ -z "$PSK" ] && command -v python3 >/dev/null 2>&1; then
            PSK="$(python3 - <<PY
import base64,os
print(base64.b64encode(os.urandom($KEY_BYTES)).decode())
PY
)"
        fi
        if [ -z "$PSK" ]; then
            err "无法生成 PSK，请确保系统安装了 openssl 或 python3，或提供密码"
            exit 1
        fi
        info "自动生成 PSK: $PSK"
    fi
}

# -----------------------
# write config
write_config(){
    CONFIG_PATH="/etc/sing-box/config.json"
    mkdir -p "$(dirname "$CONFIG_PATH")"
    cat > "$CONFIG_PATH" <<EOF
{
  "log": {"level":"info"},
  "inbounds":[{"type":"shadowsocks","listen":"::","listen_port":$PORT,"method":"$METHOD","password":"$PSK","tag":"ss2022-in"}],
  "outbounds":[{"type":"direct","tag":"direct-out"}]
}
EOF
    info "配置写入 $CONFIG_PATH"
}

# -----------------------
# install service (OpenRC for alpine, systemd otherwise)
install_service(){
    if [ "$OS" = "alpine" ]; then
        SERVICE_PATH="/etc/init.d/sing-box"
        info "生成 OpenRC 服务: $SERVICE_PATH"
        cat > "$SERVICE_PATH" <<'EOF'
#!/sbin/openrc-run
command=/usr/bin/sing-box
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
pidfile="/run/sing-box.pid"
name="sing-box"
description="Sing-box Shadowsocks Server"
depend() {
    need net
}
EOF
        chmod +x "$SERVICE_PATH"
        rc-update add sing-box default || warn "rc-update add 失败"
        rc-service sing-box start || warn "rc-service start 失败，请手动尝试：rc-service sing-box start"
        info "OpenRC 服务已尝试启动并添加开机自启"
    else
        if command -v systemctl >/dev/null 2>&1; then
            SERVICE_PATH="/etc/systemd/system/sing-box.service"
            info "生成 systemd 服务: $SERVICE_PATH"
            cat > "$SERVICE_PATH" <<'UNIT'
[Unit]
Description=Sing-box Shadowsocks Server
After=network.target

[Service]
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT
            systemctl daemon-reload || true
            systemctl enable --now sing-box || warn "systemctl enable/start 失败，请手动运行 systemctl start sing-box"
        else
            warn "未检测到 systemd，跳过自动安装服务。你可以手动用 /usr/bin/sing-box run -c /etc/sing-box/config.json 启动"
        fi
    fi
}

# -----------------------
# get public IP (best-effort)
get_public_ip(){
    for url in "https://ipinfo.io/ip" "https://ipv4.icanhazip.com" "https://ifconfig.co/ip" "https://api.ipify.org"; do
        ip=$(curl -fsm5 "$url" || true)
        if [ -n "$ip" ]; then
            echo "$ip" | tr -d '[:space:]'
            return 0
        fi
    done
    return 1
}

# -----------------------
# generate SS links
make_ss_links(){
    HOST="$1"
    TAG="singbox-ss2022"
    USERINFO="${METHOD}:${PSK}"

    if command -v python3 >/dev/null 2>&1; then
        ENC_USERINFO=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$USERINFO")
        BASE64_USERINFO=$(python3 -c "import base64,sys; s=sys.argv[1].encode(); print(base64.b64encode(s).decode())" "$USERINFO")
    else
        ENC_USERINFO=$(printf "%s" "$USERINFO" | jq -s -R -r @uri 2>/dev/null || printf "%s" "$USERINFO")
        BASE64_USERINFO=$(printf "%s" "$USERINFO" | base64 | tr -d '\n')
    fi

    SS_SIP002="ss://${ENC_USERINFO}@${HOST}:${PORT}#${TAG}"
    SS_BASE64="ss://${BASE64_USERINFO}@${HOST}:${PORT}#${TAG}"

    echo "$SS_SIP002"
    echo "$SS_BASE64"
}

# -----------------------
# main
main(){
    detect_env
    prompt_user
    install_deps
    install_singbox
    generate_psk
    write_config
    install_service

    PUB_IP="$(get_public_ip || true)"
    if [ -z "$PUB_IP" ]; then
        warn "无法自动获取公网 IP，请手动使用服务器 IP 生成客户端链接"
        PUB_IP="YOUR_SERVER_IP"
    else
        info "检测到公网 IP: $PUB_IP"
    fi

    info ""
    info "==================== 生成的 ss 链接 ===================="
    make_ss_links "$PUB_IP" | sed -e 's/^/    /'
    info "======================================================="
    info "部署完成 ✅"
    info "端口: $PORT"
    info "PSK: $PSK"
    info "配置文件: $CONFIG_PATH"
    info "服务路径: ${SERVICE_PATH:-手动启动}"
}

# run
main "$@"
