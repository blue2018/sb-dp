# VLESS-Reality 低速根因排查（test1.sh）

## 结论（先给结论）
`test1.sh` 的问题更像是 **TCP 栈调优策略与当前内核/线路组合不兼容**，并非 Reality 协议本身或硬件性能不足。

脚本把 Hy2（UDP）和 Reality（TCP）放在同一套“激进网络调优”里，但实际生效后：
- Hy2 走 UDP，通常不受 TCP 拥塞算法影响，所以表现正常。
- Reality 走 TCP + XTLS-Vision，直接受 `sysctl` 的 TCP 参数影响，容易出现“延迟不高但吞吐极低”的表现。

## 代码证据（test1.sh）

### 1) 内核不支持 BBR 时，强制退回 CUBIC
脚本逻辑：如果无 bbr/bbr2/bbr3，就使用 `cubic`。

- `net.ipv4.tcp_congestion_control = $tcp_cca`（`$tcp_cca` 可能是 `cubic`）
- 对应逻辑在 `optimize_system()` 里自动判定。

在高 RTT 跨境链路上，CUBIC 对丢包/ECN 标记更敏感，吞吐容易塌缩。

### 2) 全局强制开启 ECN
脚本固定写入：

- `net.ipv4.tcp_ecn = 1`
- `net.ipv4.tcp_ecn_fallback = 1`

现实中不少路径设备对 ECN 处理存在兼容问题，常见现象就是 **RTT 正常、TCP 速率异常低**。

### 3) 限制单连接发送队列
脚本写入：

- `net.ipv4.tcp_limit_output_bytes = 131072/262144`

在 200ms+ RTT 链路下，这个值可能进一步限制单连接吞吐上限，放大低速问题。

### 4) Reality 伪装目标域名随机，可能抽到质量差目标
Reality `server_name`/`handshake.server` 从随机域名池选取，包含：

- `www.lovelive-anime.jp` 等

这会增加连通性/握手稳定性的不确定性（尤其在某些地区线路下）。

## 先在小鸡上做的最小 A/B 验证（不改脚本）

> 目的：确认瓶颈是否来自 TCP 调优，而不是 Reality 协议本身。

### A 组（当前状态）
1. 记录当前参数：

```bash
sysctl net.ipv4.tcp_congestion_control net.ipv4.tcp_ecn net.ipv4.tcp_limit_output_bytes
```

2. 测一次 Reality 节点速度（你现有客户端方法即可）。

### B 组（仅临时回滚 3 个关键 TCP 参数）

```bash
sysctl -w net.ipv4.tcp_ecn=0
sysctl -w net.ipv4.tcp_limit_output_bytes=1048576
# 若内核支持 bbr：
sysctl -w net.ipv4.tcp_congestion_control=bbr
# 若不支持 bbr，先保持 cubic，也先看 ecn 关闭后的变化
```

然后**仅重启 sing-box**再测：

```bash
rc-service sing-box restart || systemctl restart sing-box
```

如果 Reality 速度显著回升（通常会明显高于 0.1 Mbps），即可基本确认根因在 TCP 调优组合。

## 第二个对照：固定 Reality 伪装域名
临时把 Reality 伪装域名固定成稳定目标（如 `www.microsoft.com`），避免随机命中不稳定目标。

若固定后波动明显变小，说明“随机握手目标”也是次要诱因。

## 你这个场景最可能的根因排序
1. **CUBIC + ECN + 低 `tcp_limit_output_bytes` 在高 RTT 线路下导致 TCP 吞吐塌缩**（主因）。
2. Reality 伪装域名随机命中质量较差目标（次因）。
3. 客户端链接参数兼容性（如是否明确 `encryption=none`）为小概率因素。

