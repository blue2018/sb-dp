# Sing-box SS2022 一键部署脚本（增强版）

一个强大的 Sing-box 自动化部署工具，支持落地机 Shadowsocks 部署和线路机 VLESS Reality 中转的完整解决方案。
---
落地机功能

✅ 一键安装 Sing-box + Shadowsocks 服务器
✅ 自动生成 Shadowsocks 密钥和配置
✅ 支持多系统（Alpine, Debian, Ubuntu, CentOS, RHEL, Fedora）
✅ 自动配置开机自启（Systemd / OpenRC）
✅ 自动获取公网 IP 并生成客户端链接
✅ 集成 sb 管理工具，功能齐全

线路机功能

✅ 一键生成线路机安装脚本
✅ 自动部署 VLESS + TLS Reality 入站
✅ 支持自动寻找空闲端口或手动指定
✅ 自动转发流量到落地机
✅ 生成完整的 VLESS Reality 客户端链接

## ✅ 一键部署命令

在任意支持 curl 的 Linux VPS 上运行即可安装 sing-box：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/caigouzi121380/singbox-deploy/main/install-singbox.sh)"
