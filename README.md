# Rust FRP

Rust FRP 是使用 Rust 语言实现的高性能反向代理工具，提供 TCP/HTTP/HTTPS 代理转发功能。

## 功能特性

- **TCP 代理**：将内网 TCP 服务暴露到公网，支持任意端口
- **HTTP 虚拟主机**：基于域名的 HTTP/HTTPS 路由，支持自定义域名和子域名
- **WebSocket 代理**：支持 WebSocket HTTP Upgrade，透传实时通信流量
- **STCP（安全 TCP）**：服务端中转的安全 TCP，无需在服务端开放额外端口映射
- **XTCP（P2P TCP）**：点对点直连，支持 NAT 穿透打洞，失败自动回退 STCP
- **UDP 代理**：支持 UDP 数据包双向转发，适用于游戏、DNS 等场景
- **KCP 协议**：基于 UDP 的低延迟可靠传输协议，适合弱网和跨国场景
- **TLS 加密**：使用 rustls 实现，默认使用内置自签名证书（无需额外配置即可使用），也支持自定义证书；控制连接和数据连接均默认启用加密；客户端支持跳过证书验证模式，方便使用自签名证书
- **HMAC 签名验证**：工作连接使用 HMAC-SHA256 签名，防止连接伪造
- **PROXY Protocol**：可选启用，透传真实访问者 IP 给本地 nginx/haproxy，方便日志记录和访问控制
- **工作连接池模式**：与 frp 原版一致，per-proxy mpsc channel 池管理，取后自动补充 + 失败重试
- **连接池**：内置连接池管理，支持空闲超时和生命周期控制
- **重试机制**：客户端连接本地服务时使用指数退避重试
- **端口白名单**：服务器默认拒绝未明确允许的端口，必须配置才能正常使用
- **环境变量**：配置文件支持 `${VAR_NAME}` 环境变量替换
- **多格式配置**：支持 TOML、YAML、JSON 配置格式
- **优雅关闭**：客户端支持 SIGINT/SIGTERM 信号优雅退出
- **OIDC 认证**：支持 OpenID Connect 认证，集成企业身份系统
- **配置热重载**：支持 SIGHUP 信号、文件监听、API 触发三种方式重载配置
- **健康检查**：支持 TCP 和 HTTP 健康检查，自动检测后端服务状态
- **带宽限制**：支持代理级和全局级带宽限制，基于令牌桶算法

## 功能实现状态

| 功能 | 状态 | 说明 |
|------|------|------|
| TCP 代理 | ✅ | 完整实现 |
| HTTP 代理 | ✅ | 完整实现 |
| HTTPS 代理 | ✅ | 完整实现 |
| TLS 加密 | ✅ | 使用 rustls，无需 OpenSSL |
| WebSocket | ✅ | 完整实现，支持 HTTP Upgrade |
| UDP 代理 | ✅ | 完整实现 |
| STCP (安全 TCP) | ✅ | 完整实现，服务端中转无需端口映射 |
| XTCP (P2P TCP) | ✅ | 完整实现，支持 NAT 穿透和 STCP 回退 |
| KCP 协议 | ✅ | 完整实现 |
| OIDC 认证 | ✅ | 支持 HS256 JWT 验证 |
| 配置热重载 | ✅ | 支持 SIGHUP/文件监听/API |
| 健康检查 | ✅ | 支持 TCP/HTTP 检查 |
| 带宽限制 | ✅ | 支持代理级和全局级限制 |
| PROXY Protocol | ✅ | 可选启用，透传真实访问者 IP |
| 工作连接池模式 | ✅ | per-proxy mpsc channel，取后补充+失败重试 |

---

## 项目结构

```
rust_frp/
├── rust_frp_core/          # 核心协议：消息类型、连接封装、Wire 协议
├── rust_frp_server/        # 服务端：控制连接管理、池模式工作连接、代理转发、vhost 路由
├── rust_frp_client/        # 客户端：工作连接建立、PROXY protocol、本地服务桥接
├── rust_frp_config/        # 配置：TOML/YAML/JSON 解析、验证、环境变量
├── rust_frp_net/           # 网络：TCP/TLS/WebSocket、连接池 (rustls)
├── rust_frp_auth/          # 认证：Token 认证、HMAC 签名、OIDC 认证
├── rust_frp_util/          # 工具：流桥接、重试、时间戳、随机 ID、令牌桶限速
├── rust_frp_plugin/        # 插件：HTTP/SOCKS5/TLS/StaticFile/UnixSocket 插件
├── frps.toml               # 服务器配置示例
├── frpc.toml               # 客户端配置示例
└── target/                 # 编译产物目录
```

---

## 功能应用场景

### UDP 代理 ✅

| 场景 | 说明 |
|------|------|
| 游戏服务器 | 穿透 UDP 游戏流量（如 Minecraft、CS:GO） |
| DNS 服务 | 代理内网 DNS 查询服务 |
| 流媒体 | UDP 实时音视频流转发 |
| IoT 设备 | 物联网设备 UDP 通信 |

### WebSocket 支持 ✅

| 场景 | 说明 |
|------|------|
| WebSocket 服务 | 穿透内网 WebSocket 实时通信服务 |
| HTTP 升级 | 支持从 HTTP 连接升级到 WebSocket |
| WebRTC 信令 | 转发 WebRTC 信令通道 |

### STCP/XTCP (P2P) ✅

| 场景 | 说明 |
|------|------|
| 大文件传输 | 点对点直连，减轻服务器带宽压力 |
| 低延迟通信 | 绕过中转服务器，降低延迟 |
| 隐私保护 | 数据不经过中间服务器 |
| 局域网穿透 | 两个内网设备直接通信 |

### KCP 协议 ✅

| 场景 | 说明 |
|------|------|
| 跨国连接 | 优化国际网络传输延迟 |
| 弱网环境 | 高丢包率网络下保持稳定连接 |
| 实时游戏 | 降低延迟抖动，提升游戏体验 |

### OIDC 认证 ✅

| 场景 | 说明 |
|------|------|
| 企业 SSO | 集成企业身份认证系统（如 Okta、Azure AD） |
| 多租户管理 | 支持多个组织使用同一 frp 服务 |
| 审计日志 | 与企业身份系统集成，便于审计 |

### 配置热重载 ✅

| 场景 | 说明 |
|------|------|
| 零停机部署 | 修改配置后无需重启服务 |
| 动态调整 | 运行时调整代理规则 |
| 运维友好 | 减少服务中断时间 |

### 健康检查 ✅

| 场景 | 说明 |
|------|------|
| 自动故障转移 | 检测后端服务健康状态 |
| 告警通知 | 服务异常时发送告警 |
| 负载均衡 | 配合健康检查实现负载分配 |

### 带宽限制 ✅

| 场景 | 说明 |
|------|------|
| 流量控制 | 限制单个代理的带宽使用 |
| 资源公平 | 防止某个代理占用过多带宽 |
| 成本控制 | 避免超出云服务商带宽限制 |

---

## 快速开始

### 环境要求

- Rust 1.75+
- **无需 OpenSSL**（使用纯 Rust 的 rustls 库）

### 静态编译部署

静态编译生成的可执行文件不依赖系统动态库，可直接在任何 Linux 系统上运行，无需安装依赖。

**适用场景**：
- Alpine Linux（无 glibc）
- 容器镜像（减小体积）
- 无 sudo 权限的服务器
- 需要分发单个二进制文件

```bash
# 安装 musl 目标
rustup target add x86_64-unknown-linux-musl

# 安装 musl-tools（Ubuntu/Debian）
sudo apt-get install musl-tools

# 静态编译（服务器和客户端）
cargo build --release --target x86_64-unknown-linux-musl

# 编译产物位置
ls target/x86_64-unknown-linux-musl/release/
# rust_frps（服务器）
# rust_frpc（客户端）
```

**验证静态编译**：
```bash
file target/x86_64-unknown-linux-musl/release/rust_frps
# 输出示例：ELF 64-bit LSB pie executable, x86-64, static-pie linked

ls -la target/x86_64-unknown-linux-musl/release/rust_frp*
# -rwxrwxr-x 1 user group 3.2M rust_frps  (服务器)
# -rwxrwxr-x 1 user group 3.0M rust_frpc  (客户端)
```

**静态编译优势**：
- ✅ **无系统依赖**：可在任何 Linux 发行版运行
- ✅ **Alpine 兼容**：完美支持 musl libc 环境
- ✅ **容器友好**：减小镜像体积，加速部署
- ✅ **安全可靠**：不依赖系统库更新

### Windows 交叉编译

```bash
# 安装 Windows 目标
rustup target add x86_64-pc-windows-gnu

# 安装交叉编译工具（Ubuntu/Debian）
sudo apt-get install gcc-mingw-w64-x86-64

# 编译 Windows 版本
cargo build --release --target x86_64-pc-windows-gnu

# 编译产物
ls target/x86_64-pc-windows-gnu/release/
# rust_frps.exe（服务器）
# rust_frpc.exe（客户端）
```

### 编译选项说明

| 选项 | 说明 | 适用场景 |
|------|------|----------|
| `--release` | 优化编译，生成更小更快的二进制 | 生产环境 |
| `--target x86_64-unknown-linux-musl` | 静态编译，无系统依赖 | 跨平台部署 |
| `--target x86_64-pc-windows-gnu` | 交叉编译 Windows 版本 | 为 Windows 用户分发 |
| `--features "tls"` | 启用 TLS 功能（默认已启用） | 加密通信 |

### 启动服务器

```bash
# 使用默认日志级别（info）
./target/release/rust_frps -c frps.toml

# 开启 debug 日志（用于调试）
RUST_LOG=debug ./target/release/rust_frps -c frps.toml

# 指定配置文件路径
RUST_LOG=info ./target/release/rust_frps -c /opt/rust_frp/conf/frps.toml
```

服务器默认监听：
- 控制连接：`0.0.0.0:9300`
- HTTP 虚主机：`0.0.0.0:9090`（可配置）
- HTTPS 虚主机：`0.0.0.0:9091`（可配置）

### 启动客户端

```bash
# 使用默认日志级别（info）
./target/release/rust_frpc -c frpc.toml

# 开启 debug 日志（用于调试）
RUST_LOG=debug ./target/release/rust_frpc -c frpc.toml

# 指定配置文件路径
RUST_LOG=debug ./target/release/rust_frpc -c /opt/rust_frp/conf/frpc.toml
```

### 日志级别说明

| 级别 | 说明 | 使用场景 |
|------|------|----------|
| `error` | 仅显示错误信息 | 生产环境，最小日志输出 |
| `warn` | 显示警告和错误 | 生产环境，关注潜在问题 |
| `info` | 显示一般信息 | 默认级别，了解运行状态 |
| `debug` | 显示详细调试信息 | 开发调试，排查问题 |
| `trace` | 显示所有信息 | 深度调试，性能开销较大 |

### 进程管理

使用 `systemd` 管理服务：

```ini
# /etc/systemd/system/rust_frp_client.service
[Unit]
Description=Rust FRP Client
After=network.target

[Service]
User=nobody
Group=nobody
WorkingDirectory=/opt/rust_frp
ExecStart=/opt/rust_frp/rust_frpc -c /opt/rust_frp/conf/frpc.toml
Environment=RUST_LOG=info
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

启动服务：
```bash
systemctl daemon-reload
systemctl enable rust_frp_client
systemctl start rust_frp_client
systemctl status rust_frp_client
```

---

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

---

## 服务器配置 (frps.toml)

> ⚠️ **建议**：`web_server` 默认禁用（port = 0），如需启用建议通过 Nginx 反向代理提供 HTTPS 访问。

```toml
# 服务器基本配置（必须在 [table] 之前）
bind_addr = "0.0.0.0"
bind_port = 9300
vhost_http_port = 9090
vhost_https_port = 9091
kcp_bind_port = 7001  # KCP 协议监听端口

# 端口白名单配置（默认拒绝所有未明确允许的端口）
allow_ports = [
    { single = 9302 },
    { start = 10000, end = 20000 },
]

# Web 服务器配置（默认禁用，建议通过 Nginx 反向代理提供 HTTPS）
# [web_server]
# addr = "127.0.0.1"
# port = 7500
# user = "admin"
# password = "admin"

# 传输配置
[transport]
protocol = "tcp"
bandwidth_limit = "10MB"  # 全局带宽限制
tls = { enable = true }
tcp_mux = true
pool_count = 10

# 认证配置 - Token 方式
# [auth]
# method = "token"
# token = "your_secure_token"

# 认证配置 - OIDC 方式
[auth]
method = "oidc"

[auth.oidc]
issuer = "https://your-oidc-provider.com"
audience = "frp-server"
client_id = "your-client-id"
client_secret = "your-client-secret"
token_endpoint_url = "https://your-oidc-provider.com/token"
```

---

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
bandwidth_limit = "10MB"  # 全局带宽限制
tls = { enable = true }  # 默认已启用，与原版 frp 行为一致：默认跳过证书验证

# 可选：配置自定义 CA 证书进行验证（防止中间人攻击）
# tls = { enable = true, trusted_ca_file = "/path/to/ca.crt" }

# HTTP 代理
[[proxies]]
name = "http_web"
type = "http"
local_ip = "127.0.0.1"
local_port = 8080
custom_domains = ["web.example.com"]

# TCP 代理（带带宽限制）
[[proxies]]
name = "tcp_ssh"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 22
remote_port = 9302
bandwidth_limit = "1MB"  # 代理级带宽限制（优先级高于全局）

# TCP 代理（带健康检查）
[[proxies]]
name = "tcp_app"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 8080
remote_port = 9303

[[proxies.health_check]]
type = "tcp"
interval_seconds = 10
timeout_seconds = 3
max_failed = 3

# HTTP 健康检查示例
[[proxies]]
name = "web_app"
type = "http"
local_ip = "127.0.0.1"
local_port = 8080
custom_domains = ["app.example.com"]

[[proxies.health_check]]
type = "http"
interval_seconds = 10
timeout_seconds = 3
max_failed = 3
path = "/health"
```

---

## 端口说明

| 端口 | 默认值 | 说明 |
|------|--------|------|
| `bind_port` | 9300 | **控制连接端口**：客户端连接服务器的端口 |
| `work_conn_port` | bind_port + 1000 = 10300 | **工作连接端口**：客户端与服务器建立工作代理连接的端口 |
| `vhost_http_port` | 9090 | HTTP 虚主机端口（访问内网 HTTP 服务） |
| `vhost_https_port` | 9091 | HTTPS 虚主机端口（访问内网 HTTPS 服务） |
| `kcp_bind_port` | 7001 | KCP 协议监听端口 |
| `web_server.port` | 0 (禁用) | Web Dashboard 端口（port > 0 时启用） |

> ⚠️ 注意：1024 以下端口需要 root 权限，建议使用非特权端口（如 9090/9091）。

**工作连接说明**：
- 客户端通过 `bind_port` 建立控制连接
- 客户端通过 `work_conn_port` 建立工作连接，用于代理转发
- 如果不配置 `work_conn_port`，默认使用 `bind_port + 1000`

---

## Web Dashboard

> ⚠️ **安全建议**：Dashboard **不建议直接暴露在公网**，如需远程访问，建议通过 Nginx 反向代理提供 HTTPS 访问。

### 启用方式

启用条件：`web_server.port > 0`（如设置为 7500）

Web 服务器基于 **axum** 框架实现，支持 Basic Auth 认证。

```toml
[web_server]
addr = "127.0.0.1"  # 建议仅监听本地
port = 7500
user = "admin"
password = "admin"
```

### 访问地址

- 本地访问：`http://127.0.0.1:7500`
- 远程访问：**必须通过 Nginx 反向代理**提供 HTTPS

### Nginx 反向代理配置（推荐）

```nginx
server {
    listen 443 ssl;
    server_name frp.yourdomain.com;

    # SSL 证书配置（必选）
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # Basic Auth（可选 - Nginx 和 Web 服务器可配置双重认证）
    auth_basic "FRP Dashboard";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass http://127.0.0.1:7500;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### API 接口

提供以下 API：
- `GET /health` — 健康检查
- `GET /api/metrics` — 服务器指标（连接数、代理数等）
- `GET /api/controllers` — 已连接客户端列表
- `GET /api/proxies` — 已注册代理列表
- `POST /api/reload` — 触发配置热重载

### 功能特性

- **axum 框架**：高性能异步 Web 框架
- **Basic Auth**：支持用户名密码认证保护
- **实时数据**：5 秒自动刷新看板数据
- **中文界面**：客户端和代理信息中文展示

---

## 代理类型

### TCP 代理

```toml
[[proxies]]
name = "ssh"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 22
remote_port = 9302

# 可选：启用 PROXY protocol 透传真实访问者 IP
# 本地 nginx 需配合配置：listen 80 proxy_protocol;
# proxy_protocol = true
```

### UDP 代理

```toml
[[proxies]]
name = "udp_game"
type = "udp"
local_ip = "127.0.0.1"
local_port = 25565
remote_port = 9303
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
local_port = 8080
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

### WebSocket 代理

将内网 WebSocket 服务暴露到公网，支持 HTTP Upgrade 协议升级。

```toml
[[proxies]]
name = "ws_chat"
type = "websocket"
local_ip = "127.0.0.1"
local_port = 8080
remote_port = 9304
```

### STCP（安全 TCP）

服务端中转的安全 TCP 访问，无需在服务端开放额外端口映射。通过共享密钥控制访问权限。

**代理端配置（持有内网服务的一方）**：

```toml
[[proxies]]
name = "ssh"
type = "stcp"
local_ip = "127.0.0.1"
local_port = 22
secret_key = "shared_secret_key"
```

**访问端配置（需要访问内网服务的一方）**：

```toml
[[visitors]]
name = "visit_ssh"
type = "stcp"
server_name = "ssh"            # 与代理端的 proxy name 一致
secret_key = "shared_secret_key"
bind_addr = "127.0.0.1"
bind_port = 9000              # 本地监听端口，连接此端口即可访问远程服务
```

### XTCP（P2P TCP）

点对点直连模式，优先尝试 NAT 穿透建立 P2P 连接，失败后自动回退到 STCP 服务端中转。

**代理端配置**：

```toml
[[proxies]]
name = "rdp"
type = "xtcp"
local_ip = "127.0.0.1"
local_port = 3389
secret_key = "shared_secret_key"
```

**访问端配置**：

```toml
[[visitors]]
name = "visit_rdp"
type = "xtcp"
server_name = "rdp"            # 与代理端的 proxy name 一致
secret_key = "shared_secret_key"
bind_addr = "127.0.0.1"
bind_port = 13389              # 本地监听端口
```

> **说明**：XTCP 访问者连接 `bind_port` 后，会先尝试与代理端进行 NAT 穿透打洞（2 秒超时），成功则使用 P2P 直连；失败则自动回退为 STCP 服务端中转模式。

---

## 功能实现细节

### UDP 代理

**核心实现**：

```rust
// 核心消息类型
pub struct UdpPacketMsg {
    pub proxy_name: String,
    pub data: Vec<u8>,
    pub client_addr: Option<String>,
}
```

**涉及文件**：
- `rust_frp_core/src/lib.rs` — 新增 `UdpPacketMsg`，扩展 `ProxyManager` trait
- `rust_frp_server/src/lib.rs` — UDP socket 管理，数据包转发
- `rust_frp_client/src/lib.rs` — 处理 `UdpPacket` 消息转发

**数据流**：

```text
访问者 --UDP--> 服务端(监听remote_port) --UdpPacketMsg--> 客户端 --UDP--> 本地服务
访问者 <--UDP-- 服务端(send_udp_packet) <--UdpPacketMsg-- 客户端 <--UDP-- 本地服务
```

### WebSocket 支持

**涉及文件**：
- `rust_frp_server/Cargo.toml` — 添加 `tokio-tungstenite` 依赖
- `rust_frp_net/src/lib.rs` — `WebSocketConn` 实现 `StreamLike` trait
- `rust_frp_server/src/lib.rs` — WebSocket proxy 处理

**数据流**：

```text
访问者 --WS--> 服务端(WebSocket Upgrade) --ReqWorkConn--> 客户端 --TCP--> 本地服务
访问者 <--WS-- 服务端(WebSocketConn bridge) <--WorkConn-- 客户端 <--TCP-- 本地服务
```

### KCP 协议

**核心类型**：

```rust
// KCP 连接，实现 FrpConn trait
pub struct KcpConn {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
    remote_addr: SocketAddr,
    read_buf: Vec<u8>,
}

// KCP 监听器，服务端使用
pub struct KcpListener {
    socket: Arc<tokio::net::UdpSocket>,
}
```

**KCP 参数**（默认值）：

| 参数 | 值 | 说明 |
|------|-----|------|
| nodelay | true | 启用无延迟模式 |
| interval | 10 | 内部更新间隔 (ms) |
| resend | 2 | 快速重传 |
| nc | true | 禁用拥塞控制 |
| sndwnd | 128 | 发送窗口 |
| rcvwnd | 128 | 接收窗口 |
| mtu | 1400 | 最大传输单元 |

### STCP/XTCP (P2P)

**STCP 数据流**：

```text
访问者 --TCP--> 访问者客户端(local_port) --StcpVisitorMsg--> 服务端
                                                              |
                                    服务端(StcpBridgeManager) --ReqWorkConn--> 代理端客户端
                                                              |
                          访问者客户端 <--work_conn-- 服务端(bridge) --work_conn--> 代理端客户端 --TCP--> 本地服务
```

**XTCP 数据流**：

```text
1. NAT 信息交换阶段：
   访问者 --XtcpNatInfo--> 服务端 --中继--> 代理端
   访问者 <--XtcpNatInfo-- 服务端 <--回送-- 代理端

2. P2P 打洞阶段：
   访问者 --TCP(尝试连接)--> 代理端公网地址
   代理端 --TCP(尝试连接)--> 访问者公网地址

3. P2P 成功：
   访问者 <--P2P直连--> 代理端 --TCP--> 本地服务

4. P2P 失败 → STCP 回退：
   访问者 <--work_conn-- 服务端(bridge) <--work_conn-- 代理端 --TCP--> 本地服务
```

### OIDC 认证

**JWT 验证流程**：

```text
1. 客户端从 OIDC Provider 获取 ID Token
2. 登录时发送 LoginMsg { token: "<id_token>" }
3. 服务端 OidcAuthVerifier.verify_token():
   a. 解析 JWT 三部分（header.payload.signature）
   b. 使用 HMAC-SHA256（HS256）验证签名
   c. 验证 issuer (iss claim)
   d. 验证 audience (aud claim)  
   e. 验证过期时间 (exp claim)
4. 验证通过后允许登录
```

**支持的 JWT 算法**：HS256（HMAC-SHA256），使用 `client_secret` 作为对称密钥

### 配置热重载

**触发方式**：
- **SIGHUP 信号**：`kill -HUP <pid>`
- **文件监听**：使用 `notify` 库自动监听配置文件变化
- **API 接口**：`POST /api/reload`

**热重载机制**：

```text
SIGHUP ──→ channel ──→ tokio::select! → reload_config()
文件变更 ──→ channel ──→ tokio::select! → reload_config()
POST /api/reload ──→ channel ──→ tokio::select! → reload_config()
```

**关键实现**：

```rust
// 服务端：在 TCP 连接循环中使用 tokio::select! 同时监听新连接和重载信号
tokio::select! {
    result = listener.accept() => { /* handle new connection */ }
    _ = reload_rx.recv() => { /* reload config without dropping listener */ }
}

// 客户端：在主循环中处理重载信号
tokio::select! {
    result = client.start() => { /* handle connection result */ }
    _ = reload_rx.recv() => { client.reload_config().await; continue; }
}
```

### 健康检查

**HealthCheckConfig 结构体**：

```rust
pub struct HealthCheckConfig {
    pub r#type: String,          // "tcp" 或 "http"
    pub timeout_seconds: u32,    // 超时时间（秒）
    pub max_failed: u32,         // 连续失败次数阈值
    pub interval_seconds: u32,   // 检查间隔（秒）
    pub path: Option<String>,    // HTTP 检查路径（仅 type = "http"）
}
```

**生命周期管理**：
- `Client::start()` 时自动启动所有配置了 `health_check` 的代理的健康检查
- `Client::reload_config()` 时先停止旧检查，再启动新检查（使用 `JoinHandle::abort()`）

### 带宽限制

**实现架构**：

```
客户端数据转发层
    ↓
RateLimitedReader / RateLimitedWriter  ← 对 server_read/server_write 包装
    ↓
TokenBucket（令牌桶算法）              ← 控制读写速率
```

**令牌桶算法**：
- 以恒定速率（bytes/sec）生成令牌
- 每次读写消耗对应字节数的令牌
- 令牌不足时等待补充（自动节流）
- 桶容量等于速率，防止突发流量超过限制

**限速位置**：客户端的服务器→本地（server_to_local）和本地→服务器（local_to_server）两个方向均受限速控制。优先级：代理级 `bandwidth_limit` > 全局 `bandwidth_limit`。

### PROXY Protocol

可选功能，通过 `proxy_protocol = true` 启用。在客户端连接本地服务前，写入 PROXY protocol v1 header，让 nginx/haproxy 获取真实访问者 IP 而非 `127.0.0.1`。

**数据流**：

```text
访客(1.2.3.4:54321) → frps(公网) → frpc → PROXY TCP4 1.2.3.4 127.0.0.1 54321 8080\r\n → nginx → flask
                                                                                               ↑
                                                                                    拿到真实IP 1.2.3.4
```

**涉及修改**：

- `rust_frp_config` — `proxy_protocol: Option<bool>` 配置字段
- `rust_frp_core` — `StartWorkConnMsg` 新增 `src_addr/src_port/dst_addr/dst_port`
- `rust_frp_server` — `get_work_conn` 传递访问者地址填入 StartWorkConn
- `rust_frp_client` — `establish_work_connection` 检测配置，按需写入 PROXY header

**nginx 配合配置**：

```nginx
server {
    listen 80 proxy_protocol;
    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;
}
```

**注意**：启用后本地服务必须支持 PROXY protocol（nginx 的 `proxy_protocol`、haproxy 的 `send-proxy`），否则会解析失败。

### 工作连接池模式

与 frp 原版 Go 实现对齐，服务端使用 per-proxy 有界 mpsc channel 管理工作连接。

**核心设计**：

```text
process_work_conn          get_work_conn (访客到达时)
      │                              │
      │ try_send(conn)               │ try_recv() — 池中有 → 直接取用
      ├── 池满 → 丢弃               │ pool empty → 发 ReqWorkConn → 阻塞等 recv()
      │                              │
      ▼                              ▼
   [pool channel: capacity=pool_count] → 取用后立即补充 ReqWorkConn
                                         → StartWorkConn 失败 → 重试 pool_size+1 次
```

**与 Go 原版对齐**：
- ✅ 有界 channel，满则丢弃
- ✅ 取后立即补充
- ✅ StartWorkConn 失败重试 `pool_size+1` 次
- ✅ StartWorkConn 在取用时发送（非 process 时）

**差异**：Rust 版池粒度为 per-proxy（隔离性更好），Go 版为 per-Control（整客户端共用）。

---

## 安全建议

- 使用强 Token 并定期轮换
- TLS 加密默认已启用，保护控制连接和数据连接
- **必须配置 `allow_ports` 限制可映射的端口范围**（默认拒绝所有端口）
- **Web Dashboard 配置**：
  - 仅监听本地地址（`127.0.0.1`）
  - 配置用户名密码认证
  - 通过 Nginx 反向代理提供 HTTPS 访问
  - 不要直接暴露在公网
- **TLS 证书验证**：
  - 默认模式：客户端**跳过证书验证**（与原版 frp 行为一致），开箱即用，无需额外配置
  - 自定义 CA 验证模式（`trusted_ca_file = "/path/to/ca.crt"`）：使用自定义 CA 证书验证服务器证书，可有效防止中间人攻击
  - **安全建议**：公网生产环境建议配置 `trusted_ca_file` 使用自签名证书验证，内网环境可使用默认配置
- **Token 认证**：所有连接必须通过 token 验证，即使绕过 TLS 证书验证，攻击者也无法通过认证

---

## 总结

本文档详细记录了 rust_frp 项目各功能的需求和实现状态。

**全部功能已实现** ✅

---

**文档版本**：v2.1
**更新日期**：2026-06-24

---

## 许可证

MIT License
