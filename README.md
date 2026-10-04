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
- **QUIC 协议**：基于 quinn 的 QUIC (TLS 1.3) 传输，单 UDP 连接多路复用承载控制连接与全部工作连接，适合弱网/移动网络
- **WebSocket / WSS 传输**：`protocol = "websocket"`（明文）或 `"wss"`（TLS 叠加 WebSocket，路径 `/~!frp`），在只放行 HTTP 的网关/反代后仍可建立隧道
- **wire protocol v2**：`transport.wire_protocol = "v2"` 可选启用——魔数标识 + 帧化能力协商 + HKDF 方向性 AEAD 控制通道（默认 v1，向后兼容）
- **TLS 加密**：使用 rustls 实现，未配置证书时服务端在运行时生成自签名证书（内存中、不落盘不入库），也支持自定义证书；控制连接和数据连接均默认启用加密；客户端支持跳过证书验证模式，方便使用自签名证书
- **HMAC 签名验证**：工作连接使用 HMAC-SHA256 签名，防止连接伪造
- **PROXY Protocol**：可选启用，透传真实访问者 IP 给本地 nginx/haproxy，方便日志记录和访问控制
- **工作连接池模式**：与 frp 原版一致，per-proxy mpsc channel 池管理，取后自动补充 + 失败重试
- **连接池**：内置连接池管理，支持空闲超时和生命周期控制
- **重试机制**：客户端连接本地服务时使用指数退避重试
- **端口白名单**：服务器默认拒绝未明确允许的端口，必须配置才能正常使用
- **环境变量**：配置文件支持 `${VAR_NAME}` 环境变量替换
- **多格式配置**：支持 TOML、YAML、JSON 配置格式；**兼容原版 frp 的 camelCase 字段名**（`serverAddr`/`localIP`/`bindPort` 等可直接使用），原版配置文件可直接复用；无法识别的字段（如原版 `log.to`）加载时打印 WARN 但不拒绝启动
- **优雅关闭**：客户端 SIGINT/SIGTERM 优雅退出；服务端 SIGINT/SIGTERM 停止接收新连接并按 10s 上限排空存量连接（不再硬 `exit(0)`）
- **OIDC 认证**：服务端拉取 issuer 的 Discovery + JWKS 并校验 RS256/ES256 签名（拒绝 `none`/`HS*`，防算法混淆）；客户端支持 `client_credentials` 换取访问令牌
- **tokenSource 动态令牌**：`auth.tokenSource` 支持 `type = "file"`（读文件）或 `type = "exec"`（执行命令取 stdout），避免把明文 token 写进配置文件（与静态 `token` 互斥）
- **配置热重载**：支持 SIGHUP 信号、文件监听、API 触发三种方式重载配置
- **应用层压缩**：per-proxy `use_compression`，工作连接 snappy 压缩（对齐原版语义）
- **服务端 HTTP 插件**：`[[http_plugins]]` 配置外部 HTTP 服务，在 Login/NewProxy/CloseProxy/Ping/NewWorkConn/NewUserConn 六类事件回调，支持拒绝（reject）与内容覆写（unchange）
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
| STCP (安全 TCP) | ✅ | `secret_key` HMAC-SHA256 签名校验（常量时间比较 + 120s 防重放），支持跨客户端访问 |
| XTCP (P2P TCP) | ✅ | NAT 穿透打洞 + STCP 回退可用，鉴权规则与 STCP 一致 |
| KCP 协议 | ✅ | 完整实现 |
| QUIC 协议 | ✅ | 基于 quinn 完整实现；TLS 1.3 强制（无明文模式），单 UDP 端口承载控制+工作连接，客户端 fail-closed 校验 |
| WebSocket / WSS 传输 | ✅ | `protocol = "websocket"` 明文 / `"wss"` TLS+WS；服务端在控制口按 `GET ` 前缀自动嗅探升级（TLS 场景在握手后嗅探），客户端 wss 为强制 TLS 且 fail-closed |
| wire protocol v2 | ✅ | `transport.wire_protocol = "v2"`：魔数 `FRP\x00\x02\r\n` + 帧化 ClientHello/ServerHello 能力协商 + HKDF 方向性 AEAD（aes-256-gcm）加密控制通道；服务端自动嗅探，默认 v1 兼容。**scope**：仅控制连接（工作连接仍 v1） |
| 应用层加密 | ✅ | `use_encryption`：工作连接 AES-256-GCM 加密（**仅加密不认证**，密钥派生自 token；无 token 时 fail-closed） |
| 应用层压缩 | ✅ | `use_compression`：工作连接 snappy 压缩（**需两端配置一致**；与 `use_encryption` 可叠加，顺序为先压缩后加密） |
| tcpmux 代理 | ✅ | HTTP CONNECT 复用：服务器在 `tcpmux_http_connect_port` 单端口按域名（+ 可选 `route_by_http_user` / `http_user` / `http_password`）路由，多个 tcpmux 代理共享同一端口 |
| sudp 代理 | ✅ | 安全 UDP：经 STCP 隧道承载 UDP 报文（`secret_key` 签名校验与 STCP 一致），代理端/访问端各自监听本地 UDP |
| 客户端插件 | ✅ | `unix_domain_socket`、`static_file`（路径遍历防护）、`http_proxy`（仅 CONNECT）、`socks5`、`https2http`/`tls2raw`、`https2https`、`http2http`、`http2https`（Host 改写 + 请求头注入）；认证类凭据常量时间比较 |
| 服务端 HTTP 插件 | ✅ | `[[http_plugins]]`：六类事件回调（Login/NewProxy/CloseProxy/Ping/NewWorkConn/NewUserConn），支持 `reject` 拒绝 + `unchange` 覆写；https 地址可用 `tls_verify` 控制证书校验 |
| 客户端插件认证 | ✅ | `http_proxy` 校验 `Proxy-Authorization: Basic`（失败 407）；`socks5` 按 RFC 1929 校验 `username`/`password`（失败回 `0x01/0x01`）；未配置凭据时为匿名 / 无认证（与原版一致） |
| OIDC 认证 | ✅ | 服务端：issuer Discovery + JWKS 拉取 + RS256/ES256 验签（按 `kid` 选钥、支持密钥轮转）；客户端：`client_credentials` 换取 `access_token` |
| tokenSource 动态令牌 | ✅ | `auth.tokenSource`：`type = "file"` 读文件 / `type = "exec"` 执行命令取 stdout；与静态 `token` 互斥，客户端启动与配置重载时解析（仅存内存） |
| 配置热重载 | ✅ | 支持 SIGHUP/文件监听/API |
| 健康检查 | ✅ | 支持 TCP/HTTP 检查 |
| 带宽限制 | ✅ | 支持代理级和全局级限制 |
| PROXY Protocol | ✅ | 可选启用，透传真实访问者 IP（**仅 v1**；原版 v2 未实现） |
| 原版配置兼容 | ✅ | 原版 frp 的 camelCase 字段名可直接解析（snake_case/camelCase 双向兼容）；**约 25+ 个原版字段暂未支持**，解析成功但会 WARN 提示（清单见 [`FRP_COMPARISON.md`](FRP_COMPARISON.md) 第十节） |
| frpc CLI 子命令 | ✅ | `verify`（校验配置）/ `reload`（热重载）/ `status`（代理状态）/ `stop`（优雅停止），后三者走 frpc 管理端口（Basic Auth 保护）；另有 `nathole discover`（NAT 探测）、`frpc <type> [visitor]`（单代理/访客快速启动，9 类代理）、`--config_dir`（多实例）、`--api-timeout`；**尚未支持** `--strict_config`（rust 为 WARN 模式） |
| 流量统计 | ✅ | 桥接结束累加双向字节：服务端 `/api/proxies`（`traffic_in/out`）+ Prometheus per-proxy 指标；客户端 `frpc status`（`traffic_down/up`） |
| 工作连接池模式 | ✅ | per-proxy mpsc channel，取后补充+失败重试 |

> **与原版 frp 的差距（摘要）**：数据面已基本对齐，控制/运维面覆盖约 81%。尚未支持的主要项：
> 客户端插件 `virtual_net`
> （另：`http_proxy` 仅支持 `CONNECT` 隧道，普通 HTTP 转发未实现）、服务端 tracer、
> `auth.additionalScopes`、SSH 隧道网关、`--strict_config`、Store 配置源等。
> 逐项源码级对照与本项目更严格的安全默认值，见 [`FRP_COMPARISON.md`](FRP_COMPARISON.md)。

---

## ⚠️ 安全说明（务必阅读）

| 事项 | 现状 | 建议 |
|------|------|------|
| 运行时自签证书 | 服务端未配置证书时，启动时在**内存中生成**自签证书（不落盘、不入库，每次启动更换），只能加密、**不能认证服务端身份** | 生产环境用 `transport.tls.cert_file/key_file` 指定自建证书；客户端配置 `trusted_ca_file` |
| 客户端证书校验 | **fail-closed**：配置了 TLS 但既无 `trusted_ca_file` 又未显式 `skip_verify = true` 时，客户端**拒绝启动**；`skip_verify = true` 为显式跳过（打印 WARN） | 生产环境配置 `trusted_ca_file`；自签名测试环境才用 `skip_verify = true` |
| 应用层加密 | ✅ **已实现**：`use_encryption` 对工作连接做 AES-256-GCM 加密（密钥派生自 token，**仅加密不认证**）；代理端启用时访问端须同步启用 | 与 TLS 叠加使用即可；如需认证服务端身份仍须配置 `trusted_ca_file` |
| Dashboard 凭据 | `web_server.user/password` 必须成对配置且非空，否则服务端拒绝启动；未配置则鉴权关闭并告警 | 用强密码，只监听 `127.0.0.1` 并前置 Nginx 提供 HTTPS |
| 会话机制 | 随机会话令牌 + 服务端存储 + 8 小时过期 + `HttpOnly; SameSite=Strict` | 反向代理声明 `X-Forwarded-Proto: https` 时会自动附加 `Secure` |
| 配置文件 | `frpc.toml` / `frps.toml` 已被 `.gitignore` 忽略，仅提供 `*.example.toml` | 不要把含 token/密码的配置提交进版本库 |
| STCP/XTCP 访问鉴权 | 已实现 `secret_key` 签名校验（fail-closed：代理未配 `secret_key` 时拒绝一切访问请求）；支持跨客户端访问 | 代理与访问者配置一致的强 `secret_key` |
| 插件认证 | ✅ **已强制**：`http_proxy` 校验 `Proxy-Authorization: Basic`（失败 407），`socks5` 按 RFC 1929 校验 `username`/`password`（失败回 `0x01/0x01`）；凭据一律**常量时间比较**；未配置凭据时为匿名 / 无认证 | 需要访问控制时配置强凭据；`http_proxy` 目前仅支持 `CONNECT` 隧道（普通 HTTP 转发未实现） |

---

## 项目结构

```
rust_frp/
├── rust_frp_core/          # 核心协议：消息类型、连接封装、Wire 协议
├── rust_frp_server/        # 服务端（模块化）：control 控制连接 / proxy_manager 代理管理 /
│                             web 管理端 / server 监听编排 / work_conn 连接池 / vhost 路由 /
│                             metrics 监控 / secrets STCP-XTCP 密钥 / visitor / error
├── rust_frp_client/        # 客户端：工作连接建立、PROXY protocol、本地服务桥接
├── rust_frp_config/        # 配置：TOML/YAML/JSON 解析、验证、环境变量
├── rust_frp_net/           # 网络：TCP/TLS/WebSocket/KCP/QUIC、连接池 (rustls)
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

### QUIC 协议 ✅

| 场景 | 说明 |
|------|------|
| 移动网络 | 连接迁移特性，WiFi↔4G 切网不断连 |
| 弱网高丢包 | 基于 UDP 的拥塞控制，比 TCP 更抗丢包 |
| 多路复用 | 单 UDP 连接承载控制连接与全部工作连接，无队头阻塞 |

### wire protocol v2 ✅

在 v1（`[4B 长度][JSON]` 明文控制通道）之外，新增可选的 v2 线协议用于加固控制面：

| 特性 | 说明 |
|------|------|
| 魔数标识 | 连接建立后先发 8 字节魔数 `FRP\x00\x02\r\n`；服务端自动嗅探，**无需在服务端配置** |
| 帧化握手 | 帧格式 `[2B 类型][2B 标志][4B 长度][载荷]`；ClientHello / ServerHello 完成能力协商（消息编解码器、AEAD 算法、32B 随机数） |
| 方向性 AEAD | 控制通道读写分别使用不同密钥：`HKDF-SHA256(ikm = SHA-256(token), salt = SHA-256(转录), info = "frp wire v2 control aead <算法> <方向>")`，根本排除双向复用同一 `(key, nonce)` |
| 算法 | `aes-256-gcm`；`xchacha20-poly1305` 为路线图项，协商时不会被选中 |
| 兼容性 | 默认 `v1`；v1 客户端/服务端行为零变更（服务端嗅探非魔数时把字节原样回放） |

```toml
# frpc.toml
[transport]
wire_protocol = "v2"   # "v1"（默认）或 "v2"
```

> 要求 `auth.method = "token"`（v2 的 AEAD 基础密钥派生自 `SHA-256(token)`）；
> 当前作用于**控制连接**，工作连接仍沿用 v1 帧格式。

### OIDC 认证 ✅

| 场景 | 说明 |
|------|------|
| 企业 SSO | 集成企业身份认证系统（如 Okta、Azure AD） |
| 多租户管理 | 支持多个组织使用同一 frp 服务 |
| 审计日志 | 与企业身份系统集成，便于审计 |

### tokenSource 动态令牌 ✅

| 场景 | 说明 |
|------|------|
| 避免明文令牌 | 令牌不写进配置文件，改由文件或命令提供 |
| 密钥轮转 | 配合 Secret 挂载（K8s/Vault），`frpc reload` 即重新读取 |
| 云上取令牌 | `type = "exec"` 调用云元数据 / 密钥服务动态取 token |

**配置**（与静态 `token` 互斥，二者只能配一个）：

```toml
[auth]
method = "token"

[auth.tokenSource]
type = "file"                       # 或 "exec"
filePath = "/run/secrets/frp_token"

# type = "exec" 示例：
# exec = ["/usr/local/bin/get-frp-token", "--env", "prod"]
```

### 配置热重载 ✅

**触发方式**（统一走 Client 内部 reload 通知通道）：
- **SIGHUP 信号**：`kill -HUP <pid>`
- **文件监听**：自动监听配置文件变化（500ms 防抖）
- **CLI**：`frpc reload -c frpc.toml`（走管理端口 `POST /reload`）

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

### frpc 子命令（运维）

```bash
# 校验配置文件（语法 + 校验规则，不连接服务端），失败退出码 1
./target/release/rust_frpc verify -c frpc.toml

# 热重载运行中的 frpc（走管理端口 POST /reload）
./target/release/rust_frpc reload -c frpc.toml

# 查询代理/访客运行状态（走管理端口 GET /status）
./target/release/rust_frpc status -c frpc.toml

# 停止运行中的 frpc（走管理端口 POST /stop，优雅退出）
./target/release/rust_frpc stop -c frpc.toml

# 打印版本
./target/release/rust_frpc -v
```

> 说明：`reload`/`status`/`stop` 需要 frpc 配置文件中启用管理端口
> （`[webServer] port > 0`）；配置了 `user` + `password` 时自动附带
> Basic 认证。`--api-timeout <secs>` 可调管理 API 超时（默认 30s，支持 `500ms`/`2m`）。
> 建议 `addr` 仅监听 `127.0.0.1`。

### frpc 单代理快速启动（免配置文件）

对齐原版 frp 的 `frpc <type> [flags]`：不写配置文件，直接用旗标跑单个代理或访问者。

```bash
# TCP：把本地 22 端口映射到服务器 6000
./target/release/rust_frpc tcp -s frps.example.com -p 7000 -t mytoken \
    --local_port 22 --remote_port 6000

# HTTP：按自定义域名暴露本地 8080
./target/release/rust_frpc http -s frps.example.com -p 7000 -t mytoken \
    --local_ip 127.0.0.1 --local_port 8080 \
    --custom_domains web.example.com

# STCP 访问者：本地 9000 端口访问远端名为 ssh 的 stcp 代理
./target/release/rust_frpc stcp visitor -s frps.example.com -p 7000 -t mytoken \
    --server_name ssh --bind_port 9000 --secret_key s3cr3t
```

支持的代理类型：`tcp` / `udp` / `http` / `https` / `tcpmux` / `stcp` / `sudp` / `xtcp` / `websocket`；
`stcp` / `sudp` / `xtcp` 另有 `visitor` 子命令。
长旗标同时兼容 snake_case 与原版 camelCase 拼写（如 `--local_port` 与 `--localPort`）。

### frpc 多实例（--config_dir）

```bash
# 目录内每个配置文件各起一个 frpc 实例（对齐原版 runMultipleClients）
./target/release/rust_frpc --config_dir /etc/frpc.d
```

### 打洞探测（nathole discover）

```bash
# 经 STUN 探测本机 NAT 类型与行为（EasyNAT / HardNAT、行为是否变化、是否公网）
./target/release/rust_frpc nathole discover
# 指定 STUN 服务器与本地出口地址
./target/release/rust_frpc nathole discover \
    --nat_hole_stun_server stun.example.com:3478 -l 0.0.0.0:0
```

对同一 UDP socket 依次向各 STUN 服务器探测：映射完全一致判为 `EasyNAT`，
IP/端口任一变化判为 `HardNAT` 并给出 `BehaviorIPChanged/PortChanged/BothChanged`，
与端口差 ≤5 时标记端口变化规律（可预测打洞）。

### frpc 管理 API（运行时配置 CRUD）

管理端口除上述端点外，提供对齐原版 frp 的配置管理 API：

| 端点 | 说明 |
|------|------|
| `GET /config` | 返回配置文件原文（text/plain） |
| `PUT /config` | 校验请求体为新配置 → 原子覆写配置文件 → 自动触发热重载 |
| `POST /reload` | 仅触发热重载（重读磁盘上的配置文件） |
| `POST /stop` | 触发客户端优雅退出（发送 Disconnect 后退出进程） |
| `GET /status` | 代理/访客运行状态 |

`PUT /config` 语义：**校验失败返回 400 且不落盘**（原文件保持不动）；
写盘成功返回 200 后异步重载，运行中的代理按新配置重新注册。

```bash
# 读取当前配置
curl -u admin:PASSWORD http://127.0.0.1:7400/config

# 运行时更新配置（改完即生效）
curl -u admin:PASSWORD -X PUT --data-binary @new-frpc.toml \
  http://127.0.0.1:7400/config
```

> ⚠️ **安全约束**：`GET/PUT /config` 涉及 auth token 等敏感内容与配置
> 文件覆写，**未配置 `[webServer] user/password` 时直接 403 禁用**
> （fail-closed）。启用后也建议仅监听 `127.0.0.1`（Basic 认证为明文
> HTTP 传输）。

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
quic_bind_port = 7002  # QUIC 协议监听端口（UDP，TLS 1.3 强制；未配证书时运行时自签）

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

# 认证配置 - OIDC 方式（服务端只验签，不需要 client_secret）
[auth]
method = "oidc"

[auth.oidc]
issuer = "https://your-oidc-provider.com"   # 必填
audience = "frp-server"                      # 为空则跳过 aud 校验
skipExpiryCheck = false
skipIssuerCheck = false
# trustedCaFile = "/etc/ssl/idp-ca.pem"      # IdP 使用私有 CA 时
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
tls = { enable = true, skip_verify = true }  # 自签名环境：显式跳过证书验证（默认 skip_verify = false 时未配 CA 会拒绝启动）

# 可选：配置自定义 CA 证书进行验证（防止中间人攻击，生产推荐）
# tls = { enable = true, trusted_ca_file = "/path/to/ca.crt" }

# 可选：用 tokenSource 替代明文 token（与上面 token 互斥）
# [auth.tokenSource]
# type = "file"                       # 或 "exec"
# filePath = "/run/secrets/frp_token"
# # type = "exec"
# # exec = ["/usr/local/bin/get-frp-token", "--env", "prod"]

# WebSocket / WSS 传输：将上面 protocol 改为 "websocket"（明文）或 "wss"（TLS + WS）。
# 服务端无需额外配置——它在控制端口按 `GET /~!frp` 前缀自动识别并升级。
# 说明："websocket" 仍受 [transport.tls] 控制是否叠加 TLS；"wss" 则强制 TLS，
# 且与 quic 一样必须提供信任来源（trusted_ca_file 或 skip_verify = true）。

# QUIC 传输：将上面 protocol 改为 "quic"。QUIC 强制 TLS 1.3，
# 必须提供信任来源（trusted_ca_file 或 skip_verify = true），否则拒绝启动。
# [transport.quic]
# maxIdleTimeout = 30        # 空闲超时（秒）
# maxIncomingStreams = 100000
# keepalivePeriod = 10       # 保活间隔（秒，可选）

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

# 健康检查是 [[proxies]] 的子表（单表），不要写成 [[proxies.health_check]]
[proxies.health_check]
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

[proxies.health_check]
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
| `quic_bind_port` | 7002 | QUIC 协议监听端口（UDP，TLS 1.3 强制） |
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

管理端口提供对齐原版 frp 的 v1 / v2 两套 HTTP API（`Authorization: Basic <base64(user:password)>`）：

**v1（扁平 JSON，兼容原版 Dashboard 与脚本）**

- `GET /health`、`GET /healthz` — 健康检查
- `GET /api/metrics` — 服务器指标（连接数、代理数等）
- `GET /api/serverinfo` — 服务器信息（版本、端口、代理类型计数、在线客户端数）
- `GET /api/clients?user=&clientId=&runId=&status=` — 客户端列表（含在线/离线）
- `GET /api/clients/{key}` — 客户端详情（`key = base64url(user|clientId|runId)`）
- `GET /api/controllers` — 已连接客户端列表（简版，保留兼容）
- `GET /api/proxies` — 全部代理（`status=online|offline` 可过滤）
- `GET /api/proxy/{type}` — 按类型列出代理
- `GET /api/proxy/{type}/{name}` — 按类型 + 名称查询
- `GET /api/proxies/{name}` — 按名称查询
- `GET /api/traffic/{name}` — 单代理 24 小时流量序列（`trafficIn`/`trafficOut`）
- `DELETE /api/proxies?status=offline` — 清理离线代理历史
- `POST /api/reload` — 触发配置热重载

**v2（统一 `{code, msg, data}` 信封，分页 `page`/`pageSize`，默认 1/50、上限 200）**

- `GET /api/v2/system/info` — 系统信息（`config` + `status` 两段）
- `POST /api/v2/system/prune?type=offline_proxies|clients` — 清理离线代理 / 离线客户端
- `GET /api/v2/users` — 按用户聚合（客户端数、代理数）
- `GET /api/v2/clients?status=` / `GET /api/v2/clients/{key}` — 客户端列表 / 详情
- `GET /api/v2/proxies?status=` / `GET /api/v2/proxies/{name}` — 代理列表 / 详情
- `GET /api/v2/proxies/{name}/traffic` — 单代理流量序列

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

服务端中转的安全 TCP 访问，无需在服务端开放额外端口映射。

> **访问鉴权说明**
>
> - 访问者请求时用本地 `secret_key` 对 `proxy_name + timestamp` 计算
>   HMAC-SHA256 签名，服务端用代理注册的 `secret_key` 重算并**常量时间比较**；
> - 时间戳偏差超过 **120 秒**的请求视为重放直接拒绝；
> - stcp/xtcp 代理未配置 `secret_key` 时，所有访问请求都会被拒绝（fail-closed）；
> - 支持**跨客户端**访问：访客与代理可以分属不同的 frpc 实例。
> - 若代理启用了 `use_encryption`，访问者配置也必须启用（两端密钥同源派生自各自 token，
>   且要求两侧 token 一致）。

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

> visitor 侧 NAT 信息交换同样携带 `secret_key` 签名，服务端校验通过后才会中继给代理端（鉴权规则同 STCP）。

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

### tcpmux（HTTP CONNECT 复用）

多个内网 TCP 服务通过**同一个服务器端口**暴露：客户端用 HTTP `CONNECT` 指定
目标域名，服务器按域名（以及可选的 HTTP 用户）路由到对应的 tcpmux 代理。

**服务器端**（必须显式配置复用端口，否则 tcpmux 代理注册会被拒绝）：

```toml
tcpmux_http_connect_port = 7777
```

**代理端**（持有内网服务的一方，不绑定 remote_port）：

```toml
[[proxies]]
name = "mux-ssh"
type = "tcpmux"
local_ip = "127.0.0.1"
local_port = 22
custom_domains = ["ssh.example.com"]
multiplexer = "httpconnect"      # 缺省即 httpconnect，目前仅支持该值
# 可选：要求访问者提供 HTTP Basic 凭据
# http_user = "alice"
# http_password = "s3cret"
# 可选：同一域名下按 HTTP 用户区分代理
# route_by_http_user = "alice"
```

**访问方式**：

```bash
# curl 走 HTTP CONNECT 隧道
curl -x http://服务器:7777 http://ssh.example.com/
# 或显式携带凭据（代理端配置了 http_user/http_password 时必需）
curl -x http://alice:s3cret@服务器:7777 http://ssh.example.com/

# SSH 经 CONNECT 隧道
ssh -o ProxyCommand='nc -X connect -x 服务器:7777 ssh.example.com 22' user@ssh.example.com
```

> **匹配语义**：域名先精确匹配、再按后缀匹配；`route_by_http_user` 设置后仅该
> HTTP 用户可命中该代理（用于同域多代理）；未配置任何凭据的代理对所有访问者开放。
> 应答码：`400` 请求格式错误 / `404` 域名无匹配 / `407` 凭据不符 / `502` 后端不可用。

### sudp（安全 UDP）

在 STCP 隧道之上承载 UDP：服务端仍只做工作连接配对桥接（不解析 UDP），
UDP 报文由两端 frpc 用 `UdpPacketMsg` 帧传输。适合暴露 DNS、游戏、QUIC 等 UDP 服务
而不在服务端开放 UDP 端口。

> **鉴权与加密**：访问签名规则与 STCP 完全相同（`secret_key` + 120s 防重放，
> 未配 `secret_key` 时 fail-closed 拒绝）；如需加密可两端同时启用 `use_encryption`。

**代理端配置**：

```toml
[[proxies]]
name = "udp-dns"
type = "sudp"
local_ip = "127.0.0.1"
local_port = 53
secret_key = "shared_secret_key"
```

**访问端配置**：

```toml
[[visitors]]
name = "visit-dns"
type = "sudp"
server_name = "udp-dns"       # 与代理端的 proxy name 一致
secret_key = "shared_secret_key"
bind_addr = "127.0.0.1"
bind_port = 5353              # 本地 UDP 监听端口
```

访问方式：向 `127.0.0.1:5353` 发 UDP 报文（如 `dig @127.0.0.1 -p 5353 example.com`）。

> **会话模型**：访问端每个本地 UDP 源地址占用一条独立隧道，代理端按访问者地址
> 建立独立的本地 UDP 会话（保证回包准确）；代理端每 30s 发送心跳，访问端
> 连续 60s 无消息即回收该会话。

### 服务端 HTTP 插件

frps 在处理**控制面事件**时，向外部 HTTP 服务发起同步回调，用于接入统一的
用户 / 权限 / 审计系统（对应原版 `[[httpPlugins]]`）。

**服务器端配置**：

```toml
[[http_plugins]]
name = "user-manager"
addr = "http://127.0.0.1:9000"       # 未带 scheme 时按 http:// 处理
path = "/handler"
ops = ["Login", "NewProxy", "CloseProxy", "Ping", "NewWorkConn", "NewUserConn"]
# https 地址是否校验证书（默认 false，与原版 tlsVerify 一致）
# tls_verify = false
```

**回调协议**：frps 向 `{addr}{path}?version=0.1.0&op={Op}` 发 `POST`，
请求体为 `{"version":"0.1.0","op":"Op","content":{...}}`，并附 `X-Frp-Reqid` 头；
插件须返回 `200` 与 JSON：

```json
{ "reject": false, "reject_reason": "", "unchange": true, "content": null }
```

- `reject = true`：拒绝本次操作，`reject_reason` 回传客户端
  （登录 / 注册失败即拒绝；心跳被拒 → 客户端重连；用户连接被拒 → 直接断开 / 502）；
- `unchange = false`：用 `content` 覆写内容（Login 可注入 `metas`、
  NewProxy 可改写代理配置）。

**六类事件**：

| op | 触发时机 | 可拒绝 | 可覆写 |
|----|----------|:------:|:------:|
| `Login` | 客户端通过 token 鉴权后 | ✅ | ✅ |
| `NewProxy` | 客户端注册代理时 | ✅ | ✅ |
| `CloseProxy` | 代理被移除时（单向通知） | ❌ | ❌ |
| `Ping` | 收到客户端心跳时 | ✅ | ✅ |
| `NewWorkConn` | 工作连接建立时 | ✅ | ✅ |
| `NewUserConn` | TCP / WebSocket / HTTP(S) / tcpmux 外部接入时 | ✅ | ❌ |

> **失败语义**：回调网络 / 协议失败与显式拒绝同样视为「操作失败」（fail-closed），
> 登录失败即断开、注册失败即回执错误；`CloseProxy` 为通知类，失败只记日志。
> `ops` 中出现未知操作名会导致配置校验失败（拒绝启动），避免「配了插件却静默不回调」。
> 安全：登录回调**不向插件暴露客户端 token**。

### 客户端插件

代理级 `[proxies.plugin]` 由 frpc 在本地处理访问者连接（不占用工作连接）：

| type | 说明 | 关键配置 |
|------|------|----------|
| `unix_domain_socket` | 转发到本地 Unix 域套接字 | `unix_path` |
| `static_file` | 提供静态文件（含路径遍历防护） | `local_path`、`strip_prefix`；可选 `http_user` / `http_password` 强制 Basic Auth |
| `http_proxy` | HTTP CONNECT 隧道代理 | `http_user` / `http_password`：校验 `Proxy-Authorization: Basic`，失败返回 407 |
| `socks5` | SOCKS5 代理（CONNECT，支持 IPv4 / 域名 / IPv6） | `username` / `password`：按 RFC 1929 强制认证，失败回 `0x01/0x01` |
| `https2http` / `tls2raw` | 访客 TLS 接入 → 终止 TLS → 明文桥接本地服务 | `local_addr`；`crt_path` / `key_path`（缺省内置自签证书，仅加密不认证） |
| `https2https` | 访客 TLS 接入 → 终止 TLS → 再次 TLS 连接本地服务 | 同上 |
| `http2http` | 访客明文 HTTP → 解析并重写请求 → 转发本地 **HTTP** 服务 | `local_addr`；`host_header_rewrite`；`request_headers.set.*` |
| `http2https` | 访客明文 HTTP → 解析并重写请求 → 转发本地 **HTTPS** 服务 | 同上（本地侧跳过证书校验，仅加密不认证） |

```toml
[[proxies]]
name = "local-socks5"
type = "tcp"
remote_port = 6001
[proxies.plugin]
type = "socks5"
username = "alice"
password = "CHANGE_ME_SOCKS5"
```

```toml
# http2https：把 vhost HTTP 请求改写 Host 后转发到本地 HTTPS 服务
[[proxies]]
name = "web-tls-backend"
type = "http"
custom_domains = ["test.example.com"]
[proxies.plugin]
type = "http2https"
local_addr = "127.0.0.1:443"
host_header_rewrite = "127.0.0.1"
request_headers.set.x-from-where = "frp"
```

> 认证凭据一律**常量时间比较**；未配置凭据时保持匿名（`http_proxy`）/ 无认证（`socks5`）语义，与原版一致。
> `http_proxy` 当前仅实现 `CONNECT`（HTTPS 隧道），非 CONNECT 请求返回 `405`（普通 HTTP 转发未实现）。
> `http2http` / `http2https` 支持 `Content-Length` 与 `chunked` 报文体、访客侧 keep-alive 复用；
> 到本地服务的连接按「每请求一条」建立（不做上游连接池复用），与原版行为有性能差异但语义一致。

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
- `rust_frp_net/src/lib.rs` — `WebSocketConn` 实现 `FrpConn` + `AsyncRead`/`AsyncWrite`（帧↔字节流适配，自行驱动 flush）
- `rust_frp_server/src/server.rs` — WebSocket 代理处理 + 控制口 WebSocket/WSS 升级嗅探

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

### QUIC 协议

**核心类型**（`rust_frp_net::quic`）：

```rust
// QUIC ALPN 标识
pub const QUIC_ALPN: &[u8] = b"frp";

// QUIC 连接（实现 FrpConn trait，基于 quinn SendStream/RecvStream）
pub struct QuicConn { /* ... */ }

// QUIC 监听器（服务端）：绑定 UDP 端口，accept 返回 QuicConnection
pub struct QuicListener { /* ... */ }

// QUIC 会话（客户端）：在已有连接上按需 open_stream 开工作连接
pub struct QuicSession { /* ... */ }

// 传输参数（transport.quic.*）
pub struct QuicOptions {
    pub max_idle_timeout: Duration,
    pub max_incoming_streams: u32,
    pub keep_alive_interval: Option<Duration>,
}
```

**QUIC 传输说明**：
- **TLS 1.3 强制**：QUIC 无明文模式；服务端未配证书时运行时自签（仅加密不认证）。客户端默认 fail-closed——需配 `trusted_ca_file` 或显式 `skip_verify` 才启动。
- **单端口多路复用**：控制连接与工作连接是同一条 QUIC 连接上的多个双向流（`Session::open_stream`）；服务端按每条流的首帧区分 `Login`（控制路径）与 `NewWorkConn`（工作路径）。
- **参数**（`[transport.quic]`）：`maxIdleTimeout`（默认 30s）、`maxIncomingStreams`（默认 100000）、`keepalivePeriod`（默认关闭）。

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

**服务端验签流程**（`rust_frp_auth::OidcAuthVerifier`）：

```text
1. 客户端携带令牌登录：LoginMsg { token: "<access_token / id_token>" }
2. frps 首次校验时拉取 Discovery：
     GET {issuer}/.well-known/openid-configuration → jwks_uri
   （并比对文档声明的 issuer 与配置一致）
3. GET {jwks_uri} 取 JWKS，按 JWT header 的 kid 选公钥
   （缓存 1 小时；遇到未知 kid 立即刷新，支持 IdP 轮转签名密钥）
4. 用 ring 验签：RS256（RSA PKCS#1 v1.5 + SHA-256）或 ES256（P-256 + SHA-256）
5. 校验 iss / aud / exp / nbf（skipIssuerCheck / skipExpiryCheck 可跳过）
6. 通过后记录 subject；工作连接复核 subject 必须与登录一致
```

**安全要点**：**只接受非对称签名（RS256 / ES256）**，显式拒绝 `none` 与 `HS*`——
否则攻击者把 `alg` 改成 `HS256`、拿公开的 RSA 公钥当 HMAC 密钥即可伪造令牌。

**客户端取令牌**（`rust_frp_auth::OidcClientCredentials`）：以 `client_credentials`
向 `token_endpoint_url` 发起 `POST`（`grant_type=client_credentials` + `client_id`
+ `client_secret`，可选 `audience` / `scope` / `additionalEndpointParams`），
把返回的 `access_token` 作为登录令牌；每次登录/重连都会重新获取。

**已知限制**：尚未实现 `auth.additionalScopes`（原版会在心跳 / 新工作连接上
追加刷新令牌）；工作连接的认证依赖服务端签发的 `run_id` 会话绑定。

### 配置热重载

**触发方式**：
- **SIGHUP 信号**：`kill -HUP <pid>`
- **文件监听**：使用 `notify` 库自动监听配置文件变化
- **CLI**：`frpc reload`（走客户端管理端口 `POST /reload`）

**热重载机制**：

```text
SIGHUP ──────────┐
文件变更 ─────────┼→ reload_notify (Notify) ──→ Client::start 主循环 select! → reload_config()
POST /reload ────┘
```

**关键实现**：

```rust
// 服务端：在 TCP 连接循环中使用 tokio::select! 同时监听新连接和重载信号
tokio::select! {
    result = listener.accept() => { /* handle new connection */ }
    _ = reload_rx.recv() => { /* reload config without dropping listener */ }
}

// 客户端：所有 reload 来源共用 Notify 通道，统一在 Client::start 主循环处理
// （reload 后走重连清理路径，按新配置整体重新注册，保证已删除代理下线）
tokio::select! {
    _ = async { /* login + 控制循环 */ } => { /* 连接断开 */ }
    _ = reload_notify.notified() => { reload_requested = true; }
    _ = sighup.recv() => { reload_requested = true; }
    _ = sigint.recv() => { /* graceful shutdown */ }
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
- **TLS 证书验证**（fail-closed 设计）：
  - 配置了 TLS 但既无 `trusted_ca_file` 又未显式 `skip_verify = true` 时，客户端**拒绝启动**
  - 自定义 CA 验证模式（`trusted_ca_file = "/path/to/ca.crt"`）：使用自定义 CA 证书验证服务器证书，可有效防止中间人攻击（生产推荐）
  - 显式跳过模式（`skip_verify = true`）：仅加密、不认证，任何中间人可冒充服务端，仅限测试环境
  - **安全建议**：公网生产环境配置 `trusted_ca_file` 使用自签名证书验证
- **Token 认证**：所有连接必须通过 token 验证，即使绕过 TLS 证书验证，攻击者也无法通过认证

---

## 总结

本文档记录 rust_frp 的功能与实现状态。

**核心功能（数据面 + 主要控制面）已实现并通过测试**；与原版 frp 的完整对齐情况、
未支持项清单与差距幅度见 [`FRP_COMPARISON.md`](FRP_COMPARISON.md)。

---

**文档版本**：v2.4
**更新日期**：2026-10-04

---

## 许可证

MIT License
