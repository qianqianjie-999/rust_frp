# 升级指南

本文面向生产环境中的 `rust_frps` 和 `rust_frpc` 升级。升级前应阅读
[兼容矩阵](COMPATIBILITY.md) 和 [排障手册](TROUBLESHOOTING.md)。

## 基本原则

1. 不要只检查进程是否启动，必须验证真实业务流量。
2. 保留旧版二进制、旧配置和校验值，并提前验证回滚命令。
3. 服务端先升级，确认旧客户端仍可连接后，再分批升级客户端。
4. 客户端与外部代理之间存在 HTTP 连接时，上游应显式使用 HTTP/1.1。
5. 如果运维通道本身经过被升级的 FRP 隧道，必须准备独立通道。

## 升级前检查

### 1. 记录版本

```bash
/opt/rust_frp/bin/rust_frps --version
/opt/rust_frp/bin/rust_frpc --version
sha256sum /opt/rust_frp/bin/rust_frps /opt/rust_frp/bin/rust_frpc
```

当前版本号可能无法区分不同构建。必须记录 SHA-256、构建日期和 Git commit。

### 2. 校验配置

```bash
/opt/rust_frp/bin/rust_frps verify -c /opt/rust_frp/conf/frps.toml
/opt/rust_frp/bin/rust_frpc verify -c /opt/rust_frp/conf/frpc.toml
```

### 3. 检查端口

确认以下端口可达：

- `bind_port`：控制连接
- `work_conn_port`：默认 `bind_port + 1000`
- 代理的 `remote_port`
- 本地后端端口
- 管理端口和健康检查端口

### 4. 检查反向代理

如果访问链路为：

```text
用户 -> Nginx -> rust_frps -> rust_frpc -> Apache/Flask
```

则 Nginx 必须使用 HTTP/1.1：

```nginx
location / {
    proxy_pass http://127.0.0.1:<FRPS_REMOTE_PORT>;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
}
```

修改后执行：

```bash
nginx -t
systemctl reload nginx
```

不要仅因为后端支持 HTTP/1.1 就假定 Nginx 已使用 HTTP/1.1。应通过后端访问日志
确认请求版本。

## 备份与回滚

### 备份文件

```bash
stamp=$(date +%Y%m%d-%H%M%S)
cp -a /opt/rust_frp/bin/rust_frps \
  "/opt/rust_frp/bin/rust_frps.bak-${stamp}"
cp -a /opt/rust_frp/bin/rust_frpc \
  "/opt/rust_frp/bin/rust_frpc.bak-${stamp}"
cp -a /opt/rust_frp/conf/frps.toml \
  "/opt/rust_frp/conf/frps.toml.bak-${stamp}"
cp -a /opt/rust_frp/conf/frpc.toml \
  "/opt/rust_frp/conf/frpc.toml.bak-${stamp}"
```

### 校验备份

```bash
sha256sum /opt/rust_frp/bin/rust_frps \
  "/opt/rust_frp/bin/rust_frps.bak-${stamp}"
sha256sum /opt/rust_frp/bin/rust_frpc \
  "/opt/rust_frp/bin/rust_frpc.bak-${stamp}"
```

### 回滚客户端

```bash
install -m 0755 \
  /opt/rust_frp/bin/rust_frpc.bak-<STAMP> \
  /opt/rust_frp/bin/rust_frpc

systemctl restart rust_frpc
systemctl is-active rust_frpc
sha256sum /opt/rust_frp/bin/rust_frpc
```

### 回滚服务端

```bash
install -m 0755 \
  /opt/rust_frp/bin/rust_frps.bak-<STAMP> \
  /opt/rust_frp/bin/rust_frps

systemctl restart rust_frps
systemctl is-active rust_frps
sha256sum /opt/rust_frp/bin/rust_frps
```

## 自断隧道风险

如果管理员只能通过待升级客户端暴露的 SSH 端口访问主机，重启客户端会切断当前
SSH 会话。应采用以下任一方式：

- 使用独立跳板机或带外管理通道。
- 预置升级和回滚脚本，通过 `systemd-run --on-active` 延迟执行。
- 在云控制台使用 VNC 或远程终端。

升级脚本必须支持失败回滚，并在新进程连续稳定运行后再标记成功。

## 推荐升级顺序

### 第一阶段：服务端

1. 备份服务端二进制和配置。
2. 安装新 `rust_frps`。
3. 重启服务端。
4. 确认旧客户端仍在线。
5. 观察 10–30 分钟。

### 第二阶段：低风险客户端

1. 选择业务影响较小的客户端。
2. 安装新 `rust_frpc`。
3. 重启客户端。
4. 验证控制连接和工作连接。
5. 验证实际 HTTP/TCP/WebSocket 流量。

### 第三阶段：其余客户端

按批次升级，每批完成后再进入下一批。不要一次升级全部客户端。

## 升级后验收

### 连接状态

```bash
systemctl is-active rust_frps rust_frpc
ss -Htn state established '( dport = :<BIND_PORT> )'
ss -Htn state established '( dport = :<WORK_CONN_PORT> )'
```

### 业务入口

至少验证：

- 首页
- 登录页
- 一个真实 API
- 一个静态资源
- 一个长连接或 WebSocket（如适用）

```bash
curl -k -I --max-time 10 https://127.0.0.1:<PUBLIC_PORT>/
```

### 日志

```bash
journalctl -u rust_frps --since "10 minutes ago" --no-pager \
  | grep -E 'ERROR|WARN|half-close grace'
journalctl -u rust_frpc --since "10 minutes ago" --no-pager \
  | grep -E 'ERROR|WARN'
```

生产升级建议持续验证至少 10 分钟。测试应覆盖连接复用和连接关闭，而不只是
一次首页请求。

## 判定成功

满足以下条件后才能结束升级窗口：

- 客户端和服务端保持 `active`。
- 控制连接和工作连接持续在线。
- 业务入口返回预期状态码。
- 无新增 5xx。
- 无持续半关闭告警。
- 回滚二进制和配置仍可用。
- 升级记录包含 SHA-256、commit、时间和验证结果。
