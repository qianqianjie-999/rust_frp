# 排障手册

## 先区分故障层级

建议按以下顺序检查：

1. 公网端口和 TLS
2. 公网反向代理
3. `rust_frps`
4. `rust_frpc`
5. 本地后端服务
6. 应用、数据库和网络

不要只因为 FRP 进程为 `active` 就判定链路正常。

## HTTP 页面卡住或返回 502/504

### 典型表现

- TLS 握手成功，但浏览器长时间等待。
- 公网 Nginx 报 `upstream timed out`。
- 本地后端直连正常。
- FRPS 日志出现 `half-close grace (300s) exceeded`。

### 检查入口

```bash
curl -k -I --max-time 10 https://127.0.0.1:<PUBLIC_PORT>/
curl -sS -o /dev/null -w '%{http_code}\n' \
  http://127.0.0.1:<LOCAL_APP_PORT>/
```

两项结果不一致时，问题优先看代理链路。

### 检查反向代理协议

```bash
grep -n -E 'listen|proxy_http_version|proxy_set_header Connection' \
  /etc/nginx/nginx.conf
```

HTTP 应用应使用：

```nginx
proxy_http_version 1.1;
proxy_set_header Connection "";
```

```bash
nginx -t
systemctl reload nginx
```

同时查看后端访问日志中的 HTTP 版本，确认配置实际生效。

### 检查 FRP 半关闭日志

```bash
journalctl -u rust_frps --since "10 minutes ago" --no-pager \
  | grep 'half-close grace'
```

判读方式：

- 少量且时间分散：可能是已断开的旧连接在宽限期后回收。
- 持续出现：说明后端或代理仍有大量单向关闭连接。
- 同时出现 502/504 或业务超时：需要回滚并进一步分析。

### 检查工作连接

```bash
ss -Htn state established '( dport = :<WORK_CONN_PORT> )'
ss -Htn state established '( sport = :<WORK_CONN_PORT> )'
```

工作连接不可达时，检查：

- 防火墙和安全组
- `allow_ports`
- `work_conn_port`
- `transport.work_conn_via`
- 客户端与服务端版本组合

## 客户端在线但所有代理不可用

### 检查控制面

```bash
systemctl status rust_frps rust_frpc --no-pager
journalctl -u rust_frps --since "10 minutes ago" --no-pager
journalctl -u rust_frpc --since "10 minutes ago" --no-pager
```

确认：

- 控制连接仍在
- 工作连接正在建立
- 代理注册成功
- `client_id` 没有冲突
- TLS 和 token 配置匹配

### 检查本地后端

```bash
curl -v --max-time 10 http://127.0.0.1:<LOCAL_APP_PORT>/
ss -ltnp | grep ':<LOCAL_APP_PORT>'
```

FRP 配置中的 `local_ip` 必须能从客户端机访问。不要只测试 `127.0.0.1`，还要测试
配置中实际使用的地址。

## 部分主机升级后正常，部分主机异常

这是兼容性排障，不是版本自检。至少比较：

| 维度 | 示例 |
| --- | --- |
| 客户端 SHA | 是否完全一致 |
| 客户端配置 | `local_ip`、`work_conn_via`、代理类型 |
| Web 后端 | Nginx、Gunicorn、Apache、Node.js |
| HTTP 版本 | HTTP/1.0 或 HTTP/1.1 |
| 连接头 | keep-alive、close、upgrade |
| 流量类型 | 普通请求、上传、长轮询、WebSocket |

相同 FRP 二进制在一台机器正常，不能证明其他机器不会触发兼容问题。

## 回滚

如果错误持续增长并影响业务，立即回滚客户端：

```bash
install -m 0755 \
  /opt/rust_frp/bin/rust_frpc.bak-<STAMP> \
  /opt/rust_frp/bin/rust_frpc

systemctl restart rust_frpc
systemctl is-active rust_frpc
sha256sum /opt/rust_frp/bin/rust_frpc
```

回滚后验证：

```bash
journalctl -u rust_frps --since "5 minutes ago" --no-pager \
  | grep 'half-close grace'
curl -k -I --max-time 10 https://127.0.0.1:<PUBLIC_PORT>/
```

旧连接可能在回滚后继续存在到宽限期结束。应区分旧连接回收日志和新连接错误。

## 排障记录模板

```text
故障时间：
影响入口：
用户表现：
服务端 SHA：
客户端 SHA：
配置变更：
反向代理 HTTP 版本：
本地后端直连结果：
FRPS 半关闭告警：
Nginx 5xx：
回滚版本：
恢复时间：
后续动作：
```
