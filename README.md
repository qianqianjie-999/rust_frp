# Rust FRP

Rust FRP 是使用 Rust 语言实现的高性能反向代理工具，提供 TCP/HTTP/HTTPS 代理转发功能。

## 功能特性

- **TCP 代理**：将内网 TCP 服务暴露到公网，支持任意端口
- **HTTP 虚拟主机**：基于域名的 HTTP/HTTPS 路由，支持自定义域名和子域名
- **TLS 加密**：支持内置自签名证书和自定义证书，控制连接和数据连接均可加密
- **HMAC 签名验证**：工作连接使用 HMAC-SHA256 签名，防止连接伪造
- **插件系统**：支持 Unix Domain Socket、静态文件服务、HTTP 代理、SOCKS5 代理
- **Web 管理界面**：服务器端 Dashboard 实时查看连接数、代理状态、流量统计
- **连接池**：内置连接池管理，支持空闲超时和生命周期控制
- **重试机制**：客户端连接本地服务时使用指数退避重试
- **端口白名单**：服务器可限制允许映射的端口范围
- **环境变量**：配置文件支持 `${VAR_NAME}` 环境变量替换
- **多格式配置**：支持 TOML、YAML、JSON 配置格式
- **优雅关闭**：客户端支持 SIGINT/SIGTERM 信号优雅退出

## 项目结构

```
rust_ffrp/
├── rust_frp_core/          # 核心协议：消息类型、连接封装、Wire 协议
├── rust_frp_server/        # 服务端：控制连接管理、代理转发、vhost 路由
├── rust_frp_client/        # 客户端：工作连接建立、本地服务桥接
├── rust_frp_config/        # 配置：TOML/YAML/JSON 解析、验证、环境变量
├── rust_frp_net/           # 网络：TCP/TLS/WebSocket、连接池
├── rust_frp_auth/          # 认证：Token 认证、HMAC 签名
├── rust_frp_plugin/        # 插件：Unix Socket、静态文件、HTTP代理、SOCKS5
├── rust_frp_util/          # 工具：流桥接、重试、时间戳、随机 ID
├── frps.toml               # 服务器配置示例
├── frpc.toml               # 客户端配置示例
└── bin/                    # 编译产物目录
```

## 快速开始

### 环境要求

- Rust 1.70+
- OpenSSL 开发库（`libssl-dev` 或 `openssl-devel`）

### 静态编译部署

如需静态编译（适用于 musl libc 环境如 Alpine Linux）：

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

### 启动服务器

```bash
RUST_LOG=info ./bin/rust_frps -c frps.toml
```

服务器默认监听：
- 控制连接：`0.0.0.0:9300`
- HTTP 虚主机：`0.0.0.0:9090`（可配置）
- HTTPS 虚主机：`0.0.0.0:9091`（可配置）

### 启动客户端

```bash
RUST_LOG=info ./bin/rust_frpc -c frpc.toml
```

## ⚠️ TOML 配置格式要求

**重要**：TOML 格式要求**顶级键值对必须在 `[table]` 定义之前**。

```toml
# ✅ 正确：顶级配置在 [table] 之前
bind_addr = "0.0.0.0"
bind_port = 9300
vhost_http_port = 9090

[transport]
...

[auth]
...

# ❌ 错误：顶级配置放在 [table] 之后
bind_addr = "0.0.0.0"

[auth]
method = "token"

vhost_http_port = 9090  # ❌ 解析失败！
```

## 服务器配置 (frps.toml)

```toml
# 服务器基本配置（必须在 [table] 之前）
bind_addr = "0.0.0.0"
bind_port = 9300
vhost_http_port = 9090
vhost_https_port = 9091

# Web 服务器配置（port=0 禁用，7500 启用）
[web_server]
addr = "0.0.0.0"
port = 7500
user = "admin"
password = "admin"

# 传输配置
[transport]
protocol = "tcp"
tls = { enable = true }
tcp_mux = true
pool_count = 10

# 认证配置
[auth]
method = "token"
token = "your_secure_token"
```

## 客户端配置 (frpc.toml)

```toml
# 服务器连接配置
server_addr = "123.57.86.80"
server_port = 9300

# 认证配置
[auth]
method = "token"
token = "your_secure_token"

# 传输配置
[transport]
protocol = "tcp"
tls = { enable = true }

# HTTP 代理
[[proxies]]
name = "http_web"
type = "http"
local_ip = "127.0.0.1"
local_port = 8080
custom_domains = ["web.example.com"]

# TCP 代理
[[proxies]]
name = "tcp_ssh"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 22
remote_port = 9302
```

## 端口说明

| 端口 | 默认值 | 说明 |
|------|--------|------|
| `bind_port` | 9300 | **控制连接端口**：客户端连接服务器的端口 |
| `work_conn_port` | bind_port + 1000 = 10300 | **工作连接端口**：客户端与服务器建立工作代理连接的端口 |
| `vhost_http_port` | 9090 | HTTP 虚主机端口（访问内网 HTTP 服务） |
| `vhost_https_port` | 9091 | HTTPS 虚主机端口（访问内网 HTTPS 服务） |
| `web_server.port` | 0 (禁用) | Web Dashboard 端口（port > 0 时启用） |

**工作连接说明**：
- 客户端通过 `bind_port` 建立控制连接
- 客户端通过 `work_conn_port` 建立工作连接，用于代理转发
- 如果不配置 `work_conn_port`，默认使用 `bind_port + 1000`

## Web Dashboard

启用条件：`web_server.port > 0`（如设置为 7500）

访问地址：`http://服务器IP:7500`

提供以下 API：
- `GET /health` — 健康检查
- `GET /api/metrics` — 服务器指标
- `GET /api/proxies` — 已注册代理列表

## 代理类型

### TCP 代理

```toml
[[proxies]]
name = "ssh"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 22
remote_port = 9302
```

### HTTP 虚拟主机

```toml
# 服务器端
vhost_http_port = 9090

# 客户端端
[[proxies]]
name = "web"
type = "http"
local_ip = "127.0.0.1"
local_port = 80
custom_domains = ["web.example.com"]
```

访问方式：`curl -H "Host: web.example.com" http://服务器:9090`

### HTTPS 虚拟主机

```toml
# 服务器端
vhost_https_port = 9091

[transport]
tls = { enable = true }
```

## 插件系统

### Unix Domain Socket 插件

```toml
[[proxies]]
name = "unix_proxy"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 0
remote_port = 9306

[proxies.plugin]
type = "unix_domain_socket"
unix_path = "/var/run/docker.sock"
```

### 静态文件插件

```toml
[[proxies]]
name = "file_server"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 0
remote_port = 9307

[proxies.plugin]
type = "static_file"
local_path = "/var/www/html"
strip_prefix = "/files"
```

### HTTP 代理插件

```toml
[[proxies]]
name = "http_proxy"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 0
remote_port = 9308

[proxies.plugin]
type = "http_proxy"
```

### SOCKS5 代理插件

```toml
[[proxies]]
name = "socks5"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 0
remote_port = 9309

[proxies.plugin]
type = "socks5"
```

## 安全建议

- 使用强 Token 并定期轮换
- 启用 TLS 加密保护控制连接和数据连接
- 配置 `allow_ports` 限制可映射的端口范围
- 生产环境建议不暴露 Dashboard 端口，或通过防火墙限制访问

## 许可证

MIT License
