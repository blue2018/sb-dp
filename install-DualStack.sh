# ==========================================
# 9. sb 管理工具生成 (修复版)
# ==========================================
create_manager() {
    local SHOW_NODES_CODE=$(declare -f show_nodes)
    local SHOW_SINGLE_CODE=$(declare -f show_single_node)
    local INSTALL_KERNEL_CODE=$(declare -f install_sbox_kernel)
    local READ_PORT_CODE=$(declare -f read_port)
    local ARGO_WAIT_CODE=$(declare -f wait_argo_domain)

    cat > /usr/local/bin/sb <<EOF
#!/usr/bin/env bash
CONFIG_FILE="/etc/sing-box/config.json"
SBOX_ARCH="$SBOX_ARCH"
OS_DISPLAY="$OS_DISPLAY"
SBOX_OPTIMIZE_LEVEL="$SBOX_OPTIMIZE_LEVEL"
IPV4="$IPV4"
IPV6="$IPV6"
ARGO_LOG="/etc/sing-box/argo.log"

info() { echo -e "\033[1;34m[INFO]\033[0m \$*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m \$*" >&2; }
succ() { echo -e "\033[1;32m[OK]\033[0m \$*"; }

$SHOW_NODES_CODE
$SHOW_SINGLE_CODE
$INSTALL_KERNEL_CODE
$READ_PORT_CODE
$ARGO_WAIT_CODE

restart_svc() {
    command -v systemctl >/dev/null && systemctl restart sing-box || rc-service sing-box restart
}

while true; do
    echo -e "\n\033[1;36m==============================\033[0m"
    echo "    Sing-box 管理面板 (sb)"
    echo "=============================="
    echo "1) 添加协议"
    echo "2) 查看信息"
    echo "3) 更改端口"
    echo "4) 更新内核"
    echo "5) 重启服务"
    echo "6) 卸载脚本"
    echo "0) 退出"
    read -p "选择 [0-6]: " opt

    case "\$opt" in
        1)
            HAS_HY2=\$(jq -r '.inbounds[] | select(.tag=="hy2-in") | .tag' \$CONFIG_FILE 2>/dev/null || echo "")
            HAS_ARGO=\$(jq -r '.inbounds[] | select(.tag=="vless-in") | .tag' \$CONFIG_FILE 2>/dev/null || echo "")
            echo -e "\n--- 可添加协议 ---"
            [ -z "\$HAS_HY2" ] && echo "1. Hysteria2"
            [ -z "\$HAS_ARGO" ] && echo "2. VLESS+Argo"
            echo "0. 返回上级"
            
            while true; do
                read -p "选择: " add_opt
                [ "\$add_opt" == "0" ] && break
                if [[ "\$add_opt" == "1" && -z "\$HAS_HY2" ]]; then
                    NP=\$(read_port "设置端口" "\$((RANDOM % 50000 + 10000))")
                    UUID=\$(jq -r '.inbounds[0].users[0].password // .inbounds[0].users[0].uuid' \$CONFIG_FILE 2>/dev/null || cat /proc/sys/kernel/random/uuid)
                    jq ".inbounds += [{\"type\":\"hysteria2\",\"tag\":\"hy2-in\",\"listen\":\"::\",\"listen_port\":\$NP,\"users\":[{\"password\":\"\$UUID\"}],\"tls\":{\"enabled\":true,\"alpn\":[\"h3\"],\"certificate_path\":\"/etc/sing-box/certs/fullchain.pem\",\"key_path\":\"/etc/sing-box/certs/privkey.pem\"}}]" \$CONFIG_FILE > tmp.json && mv tmp.json \$CONFIG_FILE
                    restart_svc && show_single_node "hy2-in"
                    read -p "按回车继续..." && break
                elif [[ "\$add_opt" == "2" && -z "\$HAS_ARGO" ]]; then
                    AP=\$(read_port "设置端口" "\$((RANDOM % 50000 + 10000))")
                    UUID=\$(jq -r '.inbounds[0].users[0].password // .inbounds[0].users[0].uuid' \$CONFIG_FILE 2>/dev/null || cat /proc/sys/kernel/random/uuid)
                    curl -L "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-\$SBOX_ARCH" -o /usr/bin/cloudflared && chmod +x /usr/bin/cloudflared
                    jq ".inbounds += [{\"type\":\"vless\",\"tag\":\"vless-in\",\"listen\":\"127.0.0.1\",\"listen_port\":\$AP,\"users\":[{\"uuid\":\"\$UUID\"}],\"transport\":{\"type\":\"ws\",\"path\":\"/argo\"}}]" \$CONFIG_FILE > tmp.json && mv tmp.json \$CONFIG_FILE
                    pkill cloudflared || true
                    nohup /usr/bin/cloudflared tunnel --url http://127.0.0.1:\$AP --no-autoupdate > /etc/sing-box/argo.log 2>&1 &
                    wait_argo_domain && restart_svc && show_single_node "vless-in"
                    read -p "按回车继续..." && break
                else
                    err "无效输入，请重新选择。"
                fi
            done ;;
        2) show_nodes && read -p "按回车继续..." ;;
        3)
            echo -e "\n--- 更改已安装协议端口 ---"
            HAS_HY2=\$(jq -r '.inbounds[] | select(.tag=="hy2-in") | .tag' \$CONFIG_FILE 2>/dev/null || echo "")
            HAS_ARGO=\$(jq -r '.inbounds[] | select(.tag=="vless-in") | .tag' \$CONFIG_FILE 2>/dev/null || echo "")
            opts=(); [ -n "\$HAS_HY2" ] && echo "1. Hysteria2 端口" && opts+=(1); [ -n "\$HAS_ARGO" ] && echo "2. Argo 端口" && opts+=(2); echo "0. 返回上级"
            
            while true; do
                read -p "选择: " p_opt
                [ "\$p_opt" == "0" ] && break
                if [[ " \${opts[@]} " =~ " \$p_opt " ]]; then
                    NP=\$(read_port "请输入新端口号" "\$((RANDOM % 50000 + 10000))")
                    [ "\$p_opt" == "1" ] && tag="hy2-in" || tag="vless-in"
                    jq "(.inbounds[] | select(.tag==\"\$tag\") | .listen_port) = \$NP" \$CONFIG_FILE > tmp.json && mv tmp.json \$CONFIG_FILE
                    if [ "\$tag" == "vless-in" ]; then
                        pkill cloudflared || true
                        nohup /usr/bin/cloudflared tunnel --url http://127.0.0.1:\$NP --no-autoupdate > /etc/sing-box/argo.log 2>&1 &
                        wait_argo_domain
                    fi
                    restart_svc && show_single_node "\$tag"
                    read -p "按回车继续..." && break
                else
                    err "无效选择，请重新输入。"
                fi
            done ;;
        4) 
            # 移除这里的 local，并对变量增加默认值处理
            install_sbox_kernel "true"
            ret_code=\$?
            [ "\$ret_code" -eq 0 ] && restart_svc
            read -p "按回车继续..." ;;
        5) restart_svc && succ "SingBox 服务已重启" && read -p "按回车继续..." ;;
        6) 
            read -p "确认卸载？[y/N]: " un_confirm
            if [[ "\$un_confirm" =~ ^[Yy]$ ]]; then
                info "正在卸载 SingBox 相关组件..."
                systemctl stop sing-box 2>/dev/null || rc-service sing-box stop 2>/dev/null || true
                pkill cloudflared || true
                rm -rf /etc/sing-box /usr/bin/sing-box /usr/local/bin/sb /usr/bin/cloudflared /etc/sysctl.d/99-singbox-*.conf
                sysctl --system >/dev/null 2>&1
                succ "SingBox 已彻底卸载。"
                exit 0
            else
                info "卸载已取消。"
                read -p "按回车继续..."
            fi ;;
        0) exit 0 ;;
        *) err "无效选项。" ;;
    esac
done
EOF
    chmod +x /usr/local/bin/sb
}
