# Sing-box 一键部署脚本
Sing-box 自动化部署工具，支持HY2协议。

## ✅ 一键部署命令
Hy2：
```bash
curl -fsSL -H "Cache-Control: no-cache" https://raw.githubusercontent.com/blue2018/sb-dp/refs/heads/main/hy2ech.sh -o /usr/local/bin/hy2ech.sh && chmod +x /usr/local/bin/hy2ech.sh && hy2ech.sh
```
Hy2 / VLESS + HttpUpgrade + Argo：
```bash
bash -c "$(curl -fsSL -H "Cache-Control: no-cache" https://raw.githubusercontent.com/blue2018/sb-dp/refs/heads/main/install-DualStack.sh?$(date +%s))"
```
TEST:
```bash
bash -c "$(curl -fsSL -H "Cache-Control: no-cache" https://raw.githubusercontent.com/blue2018/sb-dp/refs/heads/main/test1.sh?$(date +%s))"
```
