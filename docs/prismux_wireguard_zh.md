# Prismux + WireGuard 一键部署指南

## 为什么 Prismux 能提升游戏隧道质量

Prismux 通过以下机制提升 UDP 隧道稳定性：
1. 多路径冗余转发：同一流量可同时走两条链路。
2. 更强抗丢包能力：一条链路异常时，另一条链路仍可承载。
3. 智能分流策略：高带宽场景下不总是重复发送，减少带宽浪费。
4. 快速切换行为：链路不稳定时规则可快速转移流量。

## 拓扑说明

```text
游戏客户端 -> WireGuard(客户端/入口) -> Prismux Client -> 转发线路1 -> Prismux Server -> WireGuard(服务端/出口) -> 游戏服务器
                                                   -> 转发线路2 ->
```

## 准备条件

- 入口机器 1 台（靠近玩家）
- 出口机器 1 台（靠近游戏服务器）
- 入口到出口至少 2 条可用链路
- 两端均为 Linux，且有 `sudo` 权限
- 机器可访问公网（下载安装包和镜像）

## 一键安装与初始化

在入口和出口两端执行。脚本会自动：
- 安装 Docker 与 docker compose（缺失时）
- 安装 WireGuard（缺失时）
- 生成 WireGuard 密钥并显示本机公钥
- 交互式生成 Prismux + WireGuard 配置

### 脚本下载地址

下载并授权执行：

```bash
curl -fsSL -o prismux-wg-manager.sh https://raw.githubusercontent.com/tao08141/Prismux/main/prismux-wg-manager.sh
chmod +x prismux-wg-manager.sh
```

如果你已经在本仓库目录内，也可以直接用本地脚本：

```bash
chmod +x prismux-wg-manager.sh
```

### 两端执行安装

```bash
sudo bash ./prismux-wg-manager.sh install
```

安装流程要点：
- 两端先互换 WireGuard 公钥。
- 选择语言（English/中文）。
- 设置带宽阈值 bps（默认 `50000000`，即 50 Mbps）。
- 选择角色：`1=入口(client)`，`2=出口(server)`。
- 粘贴对端 WireGuard 公钥。
- 根据提示填写端口：
  - 入口：本地 Prismux 监听端口（默认 `7000`）、线路1/2目标（`出口IP:9000`、`出口IP:9001`）
  - 出口：线路1/2监听端口（默认 `9000/9001`）、WireGuard 服务端端口（默认 `51820`）
- WireGuard 默认地址：
  - 入口：`10.0.0.1/24`
  - 出口：`10.0.0.2/24`

生成文件：
- `/opt/prismux/docker-compose.yml`
- `/opt/prismux/config.yaml`
- `/opt/prismux/secret`
- `/opt/prismux/threshold`
- `/etc/wireguard/wg0.conf`

## 启动与开机自启

两端执行：

```bash
sudo bash ./prismux-wg-manager.sh start
```

该命令会：
- 启动 Prismux 容器
- 拉起 WireGuard（`wg0`）
- 设置 `wg-quick@wg0` 开机自启

## 常用管理命令

```bash
sudo bash ./prismux-wg-manager.sh status     # Prismux/WireGuard/端口/元信息
sudo bash ./prismux-wg-manager.sh logs       # 跟随 Prismux 日志
sudo bash ./prismux-wg-manager.sh stop       # 停止 Prismux 与 WireGuard
sudo bash ./prismux-wg-manager.sh pause      # 暂停 wg0，Prismux 保持运行
sudo bash ./prismux-wg-manager.sh resume     # 恢复 wg0
sudo bash ./prismux-wg-manager.sh update     # 拉取最新镜像并重启
sudo bash ./prismux-wg-manager.sh reload     # 重载配置（compose up -d）
sudo bash ./prismux-wg-manager.sh show-keys  # 查看本机 WireGuard 公钥
sudo bash ./prismux-wg-manager.sh lang zh    # 切换脚本语言（zh/en）
```

## 智能分流与阈值

脚本生成的 `config.yaml` 包含“带宽 + 包序号”分流规则：
- 当 `bps <= threshold`：双线路冗余发送（优先稳定）
- 当 `bps > threshold`：按 `seq % 2` 分配到两条线路（降低带宽重复）

在线更新阈值：

```bash
sudo bash ./prismux-wg-manager.sh set-threshold 80000000
sudo bash ./prismux-wg-manager.sh reload
```

## 防火墙与 UDP 端口

若使用默认参数，需放通以下 UDP 端口：
- 入口：`7000/udp`（本地 Prismux 监听，WireGuard 客户端对接 `127.0.0.1:7000`）
- 出口：`9000/udp`、`9001/udp`（两条转发线路）
- 出口：`51820/udp`（WireGuard 服务端端口）

## 连接验证

两端启动后执行：

```bash
sudo bash ./prismux-wg-manager.sh status
sudo wg show
# 从入口侧测试（默认地址）：
ping 10.0.0.2
```

## 故障排查

- 查看 Prismux 容器日志：
  ```bash
  sudo bash ./prismux-wg-manager.sh logs
  ```
- 查看 WireGuard 状态：
  ```bash
  sudo wg show
  ```
- 检查 UDP 监听端口：
  ```bash
  ss -lunpt | grep -E ":(7000|9000|9001|51820)\b" || netstat -tulpn | grep -E ":(7000|9000|9001|51820)\b"
  ```
- Docker 网络异常时：
  ```bash
  sudo systemctl restart docker
  ```

## 安全建议

- 安装器会自动生成 Prismux 鉴权密钥（两端需一致）：`/opt/prismux/secret`
- 建议定期更新镜像：
  ```bash
  sudo bash ./prismux-wg-manager.sh update
  ```
- 仅开放必要 UDP 端口，并尽量限制来源 IP。
- 定期审查运行日志。

## 可选镜像覆盖

默认镜像：

```text
ghcr.io/tao08141/prismux:latest
```

使用自定义镜像标签：

```bash
sudo PRISMUX_IMAGE=ghcr.io/tao08141/prismux:dev bash ./prismux-wg-manager.sh install
```
