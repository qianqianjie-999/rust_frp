//! # rust_frp_config - FRP 配置管理模块
//!
//! 本模块负责配置文件的解析、验证和处理。
//!
//! ## 支持的配置文件格式
//!
//! 按优先级尝试解析以下格式：
//! 1. **TOML** (推荐)
//! 2. **YAML**
//! 3. **JSON**
//!
//! ## 环境变量替换
//!
//! 配置值中可使用 `${VAR_NAME}` 语法引用环境变量：
//! ```toml
//! server_addr = "${FRP_SERVER_ADDR}"
//! token = "${FRP_TOKEN}"
//! ```
//!
//! ## 配置包含 (includes)
//!
//! 支持通过 glob 模式包含其他配置文件：
//! ```toml
//! includes = ["/etc/frp.d/*.toml"]
//! ```
//!
//! ## 默认值
//!
//! 所有配置项都有合理的默认值，可参考各结构的 `Default` 实现。

use glob::glob;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// 配置模块错误类型
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// I/O 错误
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// TOML 解析错误
    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),
    /// YAML 解析错误
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    /// JSON 解析错误
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    /// glob 模式错误
    #[error("glob pattern error: {0}")]
    Glob(#[from] glob::PatternError),
    /// 无效配置错误
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

/// 服务器配置 - 定义 FRP 服务器的所有配置选项
///
/// # 配置示例
///
/// ```toml
/// bind_addr = "0.0.0.0"
/// bind_port = 9300
/// vhost_http_port = 9090
/// vhost_https_port = 9091
///
/// [web_server]
/// addr = "0.0.0.0"
/// port = 7500
/// user = "admin"
/// password = "admin"
///
/// [transport]
/// protocol = "tcp"
/// tls = { enable = true }
/// tcp_mux = true
///
/// [auth]
/// method = "token"
/// token = "your_secure_token"
///
/// allow_ports = [
///     { single = 9302 },
///     { start = 10000, end = 20000 },
/// ]
/// ```
///
/// # 端口说明
///
/// | 端口 | 默认值 | 说明 |
/// |------|--------|------|
/// | `bind_port` | 9300 | 控制连接端口 |
/// | `work_conn_port` | bind_port + 1000 | 工作连接端口 |
/// | `vhost_http_port` | None | HTTP 虚主机端口 |
/// | `vhost_https_port` | None | HTTPS 虚主机端口 |
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct ServerConfig {
    /// 绑定地址，0.0.0.0 表示监听所有网络接口
    pub bind_addr: String,

    /// 控制连接端口，客户端通过此端口连接服务器
    pub bind_port: u16,

    /// KCP 协议绑定端口（可选，UDP）
    // TODO: KCP 协议尚未实现
    #[allow(dead_code)]
    pub kcp_bind_port: Option<u16>,

    /// QUIC 协议绑定端口（可选，UDP）
    // TODO: QUIC 协议尚未实现
    #[allow(dead_code)]
    pub quic_bind_port: Option<u16>,

    /// HTTP 虚主机端口，用于 HTTP 代理
    pub vhost_http_port: Option<u16>,

    /// HTTPS 虚主机端口，用于 HTTPS 代理
    pub vhost_https_port: Option<u16>,

    /// TCP 多路复用 HTTP 连接端口
    pub tcpmux_http_connect_port: Option<u16>,

    /// 工作连接端口，用于工作连接（默认 = bind_port + 1000）
    pub work_conn_port: Option<u16>,

    /// Web Dashboard 配置
    pub web_server: WebServerConfig,

    /// 认证配置
    pub auth: AuthConfig,

    /// 传输层配置
    pub transport: TransportConfig,

    /// 允许的端口范围列表（白名单）
    ///
    /// # 安全说明
    ///
    /// **默认拒绝所有端口**！必须显式配置才能使用 TCP 代理。
    ///
    /// # 配置示例
    ///
    /// ```toml
    /// allow_ports = [
    ///     { single = 9302 },        # 允许单个端口
    ///     { start = 10000, end = 20000 },  # 允许端口范围
    /// ]
    /// ```
    pub allow_ports: Vec<PortRange>,

    /// 单用户最大端口数限制（可选）
    ///
    /// # 说明
    ///
    /// - 限制单个用户注册的 TCP/UDP 代理数量（HTTP/HTTPS/STCP 等不占用端口配额）
    /// - 未设置或设置为 0 表示不限制
    ///
    /// # 配置示例
    ///
    /// ```toml
    /// max_ports_per_user = 5
    /// ```
    pub max_ports_per_user: Option<usize>,

    /// 自定义 404 页面路径（可选）
    pub custom_404_page: Option<String>,

    /// 配置文件包含模式（glob）
    ///
    /// # 示例
    ///
    /// ```toml
    /// includes = ["/etc/frp.d/*.toml"]
    /// ```
    pub includes: Option<Vec<String>>,

    /// 默认代理配置列表
    pub proxies: Vec<ProxyConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0".to_string(),
            bind_port: 7000,
            kcp_bind_port: None,
            quic_bind_port: None,
            vhost_http_port: None,
            vhost_https_port: None,
            tcpmux_http_connect_port: None,
            work_conn_port: None,
            web_server: WebServerConfig::default(),
            auth: AuthConfig::default(),
            transport: TransportConfig::default(),
            allow_ports: Vec::new(),
            max_ports_per_user: None,
            custom_404_page: None,
            includes: None,
            proxies: Vec::new(),
        }
    }
}

/// 客户端配置 - 定义 FRP 客户端的所有配置选项
///
/// # 配置示例
///
/// ```toml
/// server_addr = "123.57.86.80"
/// server_port = 9300
///
/// [auth]
/// method = "token"
/// token = "your_secure_token"
///
/// [transport]
/// protocol = "tcp"
/// tls = { enable = true }
///
/// [[proxies]]
/// name = "ssh"
/// type = "tcp"
/// local_ip = "127.0.0.1"
/// local_port = 22
/// remote_port = 9302
/// ```
///
/// # 代理类型
///
/// - `tcp`: TCP 代理
/// - `udp`: UDP 代理
/// - `http`: HTTP 代理
/// - `https`: HTTPS 代理
/// - `stcp`: 秘密 TCP（需要访问者知道密钥）
/// - `xtcp`: P2P TCP
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct ClientConfig {
    /// 服务器地址
    pub server_addr: String,

    /// 服务器控制连接端口
    pub server_port: u16,

    /// 服务器工作连接端口（可选）
    ///
    /// # 说明
    ///
    /// - 未设置时默认使用 server_port + 1000
    /// - 需与服务端 frps.toml 的 work_conn_port 一致
    pub work_conn_port: Option<u16>,

    /// 用户名（可选，用于多用户场景）
    pub user: Option<String>,

    /// 客户端 ID（可选，用于多客户端场景）
    pub client_id: Option<String>,

    /// Web Dashboard 配置（可选）
    pub web_server: WebServerConfig,

    /// 认证配置
    pub auth: AuthConfig,

    /// 传输层配置
    pub transport: TransportConfig,

    /// 代理配置列表
    pub proxies: Vec<ProxyConfig>,

    /// 访问者配置列表
    ///
    /// # 访问者说明
    ///
    /// 访问者用于访问其他客户端暴露的服务（STCP/XTCP 代理类型）
    pub visitors: Vec<VisitorConfig>,

    /// 配置文件包含模式
    pub includes: Option<Vec<String>>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1".to_string(),
            server_port: 7000,
            work_conn_port: None,
            user: None,
            client_id: None,
            web_server: WebServerConfig::default(),
            auth: AuthConfig::default(),
            transport: TransportConfig::default(),
            proxies: Vec::new(),
            visitors: Vec::new(),
            includes: None,
        }
    }
}

/// Web Dashboard 配置
///
/// # 启用条件
///
/// `port > 0` 时启用 Dashboard 服务
///
/// # 访问地址
///
/// `http://{addr}:{port}`
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(default)]
pub struct WebServerConfig {
    /// 监听地址
    pub addr: String,

    /// 监听端口（0 = 禁用）
    pub port: u16,

    /// Dashboard 用户名
    pub user: Option<String>,

    /// Dashboard 密码
    pub password: Option<String>,
}

/// 认证配置 - 定义客户端认证方式
///
/// # 认证方法
///
/// - `token`: 基于令牌的认证（默认）
/// - `oidc`: 基于 OpenID Connect 的认证
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct AuthConfig {
    /// 认证方法："token" 或 "oidc"
    pub method: String,

    /// 令牌（当 method = "token" 时使用）
    pub token: Option<String>,

    /// OIDC 配置（当 method = "oidc" 时使用）
    pub oidc: Option<OidcConfig>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            method: "token".to_string(),
            token: None,
            oidc: None,
        }
    }
}

/// OpenID Connect 配置
///
/// # 说明
///
/// OIDC 是一种基于 OAuth 2.0 的身份认证协议，适用于企业 SSO 场景。
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(default)]
pub struct OidcConfig {
    /// 发行者 URL
    pub issuer: String,

    /// 受众
    pub audience: String,

    /// OAuth 客户端 ID
    pub client_id: String,

    /// OAuth 客户端密钥
    pub client_secret: String,

    /// Token 端点 URL
    pub token_endpoint_url: String,
}

/// 传输层配置 - 定义网络传输相关选项
///
/// # TCP 多路复用 (tcp_mux)
///
/// 启用后，多个请求共享同一个 TCP 连接，减少连接开销：
///
/// ```text
/// 启用前:  客户端 --TCP-- 服务器 (每个请求独立连接)
/// 启用后:  客户端 --TCP-- 服务器 (多请求复用连接)
/// ```
///
/// # 连接池 (pool_count)
///
/// 客户端预建立的工作连接数量，范围 1-1000
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct TransportConfig {
    /// 传输协议: "tcp", "kcp", "quic", "websocket"
    pub protocol: String,

    /// TLS 配置
    ///
    /// # 安全说明
    ///
    /// **TLS 默认已启用**（enable = true）
    pub tls: Option<TlsConfig>,

    /// 启用 TCP 多路复用
    ///
    /// 多个业务流共享单个 TCP 连接，减少握手延迟
    pub tcp_mux: bool,

    /// 强制 TLS（仅服务端有效，对齐 frp 的 transport.tls.force）
    ///
    /// # 说明
    ///
    /// - 开启后所有连接（含工作连接）必须使用 TLS，明文连接将被拒绝
    /// - 前置条件：`tls.enable = true`，否则启动报错
    ///
    /// # 配置示例
    ///
    /// ```toml
    /// [transport.tls]
    /// enable = true
    /// # tls_only = true
    /// ```
    pub tls_only: bool,

    /// 连接池大小
    ///
    /// 客户端预建立的工作连接数量。建议值：5-100
    pub pool_count: u32,

    /// 带宽限制（可选），格式如 "1MB" 或 "1GB"
    pub bandwidth_limit: Option<String>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            protocol: "tcp".to_string(),
            tls: None,
            tcp_mux: true,
            tls_only: false,
            pool_count: 10,
            bandwidth_limit: None,
        }
    }
}

/// TLS 配置 - 定义 TLS/SSL 加密选项
///
/// # 模式
///
/// ## 1. 内置自签名证书（默认）
///
/// 服务器使用内置的自签名证书，客户端自动信任。
///
/// ## 2. 自定义证书
///
/// ```toml
/// tls = {
///     enable = true,
///     cert_file = "/path/to/cert.pem",
///     key_file = "/path/to/key.pem"
/// }
/// ```
///
/// ## 3. 自定义 CA 证书
///
/// ```toml
/// tls = {
///     enable = true,
///     trusted_ca_file = "/path/to/ca.pem"
/// }
/// ```
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct TlsConfig {
    /// 是否启用 TLS
    ///
    /// # 默认值
    ///
    /// **true** - TLS 默认启用
    pub enable: bool,

    /// TLS 证书文件路径（服务器用）
    pub cert_file: Option<String>,

    /// TLS 私钥文件路径（服务器用）
    pub key_file: Option<String>,

    /// 受信任的 CA 证书文件路径（客户端用）
    ///
    /// 用于验证服务器证书
    pub trusted_ca_file: Option<String>,

    /// 是否跳过服务器证书验证（客户端用）
    ///
    /// 适用于使用自定义自签名证书的场景，仅加密连接，不验证证书
    ///
    /// # 默认值
    ///
    /// **false** - 默认验证服务器证书
    pub skip_verify: bool,

    /// 强制使用 TLS（即使协议不支持 TLS）
    pub force: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enable: true,
            cert_file: None,
            key_file: None,
            trusted_ca_file: None,
            skip_verify: false,
            force: false,
        }
    }
}

/// 端口范围 - 定义单个端口或端口范围
///
/// # 格式
///
/// ## 单端口
/// ```toml
/// { single = 9302 }
/// ```
///
/// ## 端口范围
/// ```toml
/// { start = 10000, end = 20000 }
/// ```
///
/// # 合并行为
///
/// 单端口 `{ single = 80 }` 等价于 `{ start = 80, end = 80 }`
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(default)]
pub struct PortRange {
    /// 范围起始端口（包含）
    pub start: Option<u16>,

    /// 范围结束端口（包含）
    pub end: Option<u16>,

    /// 单个端口（与 start/end 互斥）
    pub single: Option<u16>,
}

/// 代理配置 - 定义单个代理的转发规则
///
/// # 代理类型
///
/// ## TCP 代理
///
/// ```toml
/// [[proxies]]
/// name = "ssh"
/// type = "tcp"
/// local_ip = "127.0.0.1"
/// local_port = 22
/// remote_port = 9302
/// ```
///
/// ## HTTP 代理
///
/// ```toml
/// [[proxies]]
/// name = "web"
/// type = "http"
/// local_ip = "127.0.0.1"
/// local_port = 80
/// custom_domains = ["web.example.com"]
/// ```
///
/// # 字段说明
///
/// - `name`: 代理唯一名称
/// - `type`: 代理类型 (tcp/udp/http/https/websocket/stcp/xtcp)
/// - `local_ip`: 本地服务 IP
/// - `local_port`: 本地服务端口
/// - `remote_port`: 远程映射端口（TCP/UDP/WebSocket 必需，stcp/xtcp 不需要）
/// - `secret_key`: 共享密钥（stcp/xtcp 代理用于认证）
/// - `custom_domains`: 自定义域名（HTTP/HTTPS 代理用）
/// - `subdomain`: 子域名（HTTP/HTTPS 代理用）
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(default)]
pub struct ProxyConfig {
    /// 代理唯一名称
    pub name: String,

    /// 代理类型
    ///
    /// 可选值：
    /// - `tcp`: TCP 代理
    /// - `udp`: UDP 代理
    /// - `http`: HTTP 代理
    /// - `https`: HTTPS 代理
    /// - `stcp`: 秘密 TCP（需要访问密钥）
    /// - `xtcp`: P2P TCP
    #[serde(rename = "type")]
    pub r#type: String,

    /// 本地服务 IP 地址
    pub local_ip: String,

    /// 本地服务端口
    pub local_port: u16,

    /// 远程映射端口（TCP/UDP 代理必需）
    pub remote_port: Option<u16>,

    /// 自定义域名列表（HTTP/HTTPS 代理用）
    ///
    /// # 示例
    ///
    /// ```toml
    /// custom_domains = ["web.example.com", "api.example.com"]
    /// ```
    pub custom_domains: Option<Vec<String>>,

    /// 子域名（HTTP/HTTPS 代理用）
    ///
    /// 配合服务器的 `subdomain_base` 使用
    pub subdomain: Option<String>,

    /// URL 路径匹配规则（HTTP 代理用）
    ///
    /// # 示例
    ///
    /// ```toml
    /// locations = ["/api", "/static"]
    /// ```
    pub locations: Option<Vec<String>>,

    /// 改写 Host header（HTTP 代理用）
    pub host_header_rewrite: Option<String>,

    /// HTTP 基本认证用户名（HTTP 代理用）
    pub http_user: Option<String>,

    /// HTTP 基本认证密码（HTTP 代理用）
    pub http_password: Option<String>,

    /// 健康检查配置（可选）
    pub health_check: Option<HealthCheckConfig>,

    /// 带宽限制（可选），格式如 "1MB"、"500KB"、"10GB"
    ///
    /// 限制该代理的最大传输速率，覆盖全局 bandwidth_limit
    pub bandwidth_limit: Option<String>,

    /// 共享密钥（stcp/xtcp 代理用）
    pub secret_key: Option<String>,

    /// 传输层覆盖配置（可选）
    ///
    /// 覆盖全局 transport 配置
    pub transport: Option<TransportConfig>,

    /// 插件配置（可选）
    ///
    /// 当使用插件时，local_ip/local_port 被插件替代
    pub plugin: Option<PluginConfig>,

    /// 是否启用 PROXY protocol（可选，默认 false）
    ///
    /// 启用后，frpc 在连接本地服务前会写入 PROXY protocol v1 header，
    /// 让 nginx/haproxy 等本地服务获取真实访问者 IP。
    ///
    /// # 示例
    ///
    /// ```toml
    /// proxy_protocol = true
    /// ```
    ///
    /// 本地 nginx 需要配合配置：
    /// ```nginx
    /// listen 80 proxy_protocol;
    /// set_real_ip_from 127.0.0.1;
    /// real_ip_header proxy_protocol;
    /// ```
    pub proxy_protocol: Option<bool>,

    /// 负载均衡分组名（可选，仅 TCP 代理）
    ///
    /// 同 group + 同 remote_port 的多个代理组成负载均衡组，
    /// 服务器对新连接按 round-robin 分发到组成员。
    ///
    /// # 示例
    ///
    /// ```toml
    /// [[proxies]]
    /// name = "web-1"
    /// type = "tcp"
    /// group = "web"
    /// group_key = "shared-secret"
    /// remote_port = 8080
    /// ```
    pub group: Option<String>,

    /// 负载均衡分组密钥（可选，与 group 配合）
    ///
    /// 加入组时校验，与已有成员不匹配则拒绝注册（防止误入他人分组）。
    pub group_key: Option<String>,
}

/// 访问者配置 - 定义如何访问其他客户端的 STCP/XTCP 服务
///
/// # 使用场景
///
/// 当需要访问部署在其他机器上的 STCP/XTCP 类型代理时使用：
///
/// ```toml
/// [[visitors]]
/// name = "visit_ssh"
/// type = "stcp"
/// server_name = "ssh"           # 被访问的代理名称
/// secret_key = "your_secret"    # 访问密钥
/// bind_addr = "127.0.0.1"
/// bind_port = 9000              # 本地监听端口
/// ```
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(default)]
pub struct VisitorConfig {
    /// 访问者唯一名称
    pub name: String,

    /// 访问者类型：stcp 或 xtcp
    pub r#type: String,

    /// 要访问的代理名称（需与对方客户端配置匹配）
    pub server_name: String,

    /// 共享密钥（需与对方代理配置匹配）
    pub secret_key: Option<String>,

    /// 本地绑定地址
    pub bind_addr: String,

    /// 本地监听端口
    ///
    /// 访问者连接此端口即可访问远程服务
    pub bind_port: u16,

    /// 传输层配置（可选）
    pub transport: Option<TransportConfig>,
}

/// 健康检查配置 - 定义代理健康检查规则
///
/// # 使用场景
///
/// 用于检查本地服务是否正常响应，不健康时自动剔除
///
/// # 字段说明
///
/// - `type`: 检查类型 "tcp" 或 "http"
/// - `timeout_seconds`: 超时时间
/// - `max_failed`: 连续失败次数阈值
/// - `interval_seconds`: 检查间隔
/// - `path`: HTTP 检查路径（仅 http 类型）
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(default)]
pub struct HealthCheckConfig {
    /// 检查类型: "tcp" 或 "http"
    pub r#type: String,

    /// 超时时间（秒）
    pub timeout_seconds: u32,

    /// 连续失败次数阈值
    ///
    /// 超过此值则判定为不健康
    pub max_failed: u32,

    /// 检查间隔（秒）
    pub interval_seconds: u32,

    /// HTTP 检查路径（仅 type = "http" 时使用）
    pub path: Option<String>,
}

/// 插件配置 - 定义代理使用的插件
///
/// # 内置插件
///
/// ## Unix Domain Socket
///
/// ```toml
/// [proxy.plugin]
/// type = "unix_domain_socket"
/// unix_path = "/var/run/docker.sock"
/// ```
///
/// ## 静态文件服务器
///
/// ```toml
/// [proxy.plugin]
/// type = "static_file"
/// local_path = "/var/www/html"
/// strip_prefix = "/files"
/// ```
///
/// ## HTTP 代理
///
/// ```toml
/// [proxy.plugin]
/// type = "http_proxy"
/// ```
///
/// ## SOCKS5 代理
///
/// ```toml
/// [proxy.plugin]
/// type = "socks5"
/// ```
///
/// # 说明
///
/// 使用插件后，`local_ip` 和 `local_port` 被插件替代。
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(default)]
pub struct PluginConfig {
    /// 插件类型
    ///
    /// 可选值：
    /// - `unix_domain_socket`: Unix 域套接字
    /// - `static_file`: 静态文件服务
    /// - `http_proxy`: HTTP 代理
    /// - `socks5`: SOCKS5 代理
    /// - `https2http`: TLS 卸载（访客 HTTPS → 明文 HTTP 本地服务）
    /// - `tls2raw`: TLS 卸载（访客 TLS → 明文 TCP 本地服务，与 https2http 同实现）
    /// - `https2https`: 双层 TLS 桥接（访客 HTTPS → TLS 本地服务）
    pub r#type: String,

    /// Unix 域套接字路径（unix_domain_socket 插件用）
    pub unix_path: Option<String>,

    /// 本地文件路径（static_file 插件用）
    pub local_path: Option<String>,

    /// 路径前缀剥离（static_file 插件用）
    pub strip_prefix: Option<String>,

    /// HTTP 用户名（http_proxy 插件用）
    pub http_user: Option<String>,

    /// HTTP 密码（http_proxy 插件用）
    pub http_password: Option<String>,

    /// 本地地址（http_proxy/socks5 及 TLS 系插件 https2http/tls2raw/https2https 用）
    pub local_addr: Option<String>,

    /// 证书文件路径（HTTPS 相关插件用）
    pub crt_path: Option<String>,

    /// 私钥文件路径（HTTPS 相关插件用）
    pub key_path: Option<String>,
}

/// 配置加载器 - 负责配置的加载、解析和验证
///
/// # 功能
///
/// 1. 支持 TOML/YAML/JSON 多种格式
/// 2. 支持配置包含（glob 模式）
/// 3. 支持环境变量替换
/// 4. 配置验证
pub struct ConfigLoader;

impl ConfigLoader {
    /// 从文件加载服务器配置
    ///
    /// # 处理流程
    ///
    /// ```text
    /// 文件读取 -> 格式检测 -> 解析 -> includes合并 -> 环境变量替换 -> 验证
    /// ```
    ///
    /// # 参数
    ///
    /// - `path`: 配置文件路径
    ///
    /// # 返回值
    ///
    /// - 成功: `Ok(ServerConfig)`
    /// - 失败: `Box<dyn Error>`
    ///
    /// # 示例
    ///
    /// ```rust,ignore
    /// let config = ConfigLoader::load_server_config("frps.toml")?;
    /// ```
    pub fn load_server_config<P: AsRef<Path>>(
        path: P,
    ) -> Result<ServerConfig, Box<dyn std::error::Error>> {
        let mut config: ServerConfig = Self::load_config_from_file(path)?;
        Self::process_includes(&mut config)?;
        Self::replace_environment_variables(&mut config)?;
        Self::validate_server_config(&config)?;
        Ok(config)
    }

    /// 从文件加载客户端配置
    ///
    /// # 处理流程
    ///
    /// 与 `load_server_config` 类似，但针对客户端配置结构
    pub fn load_client_config<P: AsRef<Path>>(
        path: P,
    ) -> Result<ClientConfig, Box<dyn std::error::Error>> {
        let mut config = Self::load_config_from_file(path)?;
        Self::process_includes_client(&mut config)?;
        Self::replace_environment_variables_client(&mut config)?;
        Self::validate_client_config(&config)?;
        Ok(config)
    }

    /// 从文件加载配置（通用方法）
    ///
    /// # 格式检测
    ///
    /// 按 TOML -> YAML -> JSON 顺序尝试解析
    ///
    /// # 性能优化
    ///
    /// 首次成功的格式会被记录，避免重复尝试
    fn load_config_from_file<P: AsRef<Path>, T: serde::de::DeserializeOwned + Default>(
        path: P,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let mut file = File::open(path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        log::debug!("Raw config content: {}", content);
        Self::parse_config(&content)
    }

    /// 解析配置内容
    ///
    /// # 格式优先级
    ///
    /// 1. TOML（首选，推荐）
    /// 2. YAML
    /// 3. JSON
    ///
    /// # 错误处理
    ///
    /// 所有格式都失败时返回错误
    fn parse_config<T: serde::de::DeserializeOwned + Default>(
        content: &str,
    ) -> Result<T, Box<dyn std::error::Error>> {
        // 尝试 TOML
        log::info!("Trying to parse config as TOML");
        if let Ok(config) = toml::from_str::<T>(content) {
            log::info!("Successfully parsed config as TOML");
            return Ok(config);
        }
        log::error!("Failed to parse as TOML");

        // 尝试 YAML
        log::info!("Trying to parse config as YAML");
        if let Ok(config) = serde_yaml::from_str::<T>(content) {
            log::info!("Successfully parsed config as YAML");
            return Ok(config);
        }
        log::error!("Failed to parse as YAML");

        // 尝试 JSON
        log::info!("Trying to parse config as JSON");
        if let Ok(config) = serde_json::from_str(content) {
            log::info!("Successfully parsed config as JSON");
            return Ok(config);
        }
        log::error!("Failed to parse as JSON");

        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Failed to parse config file",
        )))
    }

    /// 处理服务器配置文件包含
    ///
    /// # includes 机制
    ///
    /// 通过 glob 模式匹配多个配置文件并合并：
    ///
    /// ```toml
    /// includes = ["/etc/frp.d/*.toml", "/home/*/frp.conf"]
    /// ```
    ///
    /// # 合并规则
    ///
    /// - 标量值：后者覆盖前者
    /// - 数组（如 proxies）：扩展合并
    fn process_includes(config: &mut ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
        let includes = config.includes.clone();
        if let Some(includes) = includes {
            for pattern in includes {
                let files = glob(&pattern)?;
                for file in files {
                    match file {
                        Ok(path) => {
                            let include_config = Self::load_config_from_file(path)?;
                            Self::merge_server_config(config, &include_config);
                        }
                        Err(e) => {
                            log::warn!("glob error: {:?}", e);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// 处理客户端配置文件包含
    ///
    /// 与 `process_includes` 类似，但针对客户端配置
    fn process_includes_client(
        config: &mut ClientConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let includes = config.includes.clone();
        if let Some(includes) = includes {
            for pattern in includes {
                let files = glob(&pattern)?;
                for file in files {
                    match file {
                        Ok(path) => {
                            let include_config = Self::load_config_from_file(path)?;
                            Self::merge_client_config(config, &include_config);
                        }
                        Err(e) => {
                            log::warn!("glob error: {:?}", e);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// 合并服务器配置
    ///
    /// # 合并策略
    ///
    /// - 值为零值或空时不覆盖
    /// - 数组字段（如 proxies）使用 extend 合并
    fn merge_server_config(target: &mut ServerConfig, source: &ServerConfig) {
        if !source.bind_addr.is_empty() {
            target.bind_addr = source.bind_addr.clone();
        }
        if source.bind_port != 0 {
            target.bind_port = source.bind_port;
        }
        if source.kcp_bind_port.is_some() {
            target.kcp_bind_port = source.kcp_bind_port;
        }
        if source.quic_bind_port.is_some() {
            target.quic_bind_port = source.quic_bind_port;
        }
        if source.vhost_http_port.is_some() {
            target.vhost_http_port = source.vhost_http_port;
        }
        if source.vhost_https_port.is_some() {
            target.vhost_https_port = source.vhost_https_port;
        }
        if source.tcpmux_http_connect_port.is_some() {
            target.tcpmux_http_connect_port = source.tcpmux_http_connect_port;
        }
        target.proxies.extend(source.proxies.clone());
    }

    /// 合并客户端配置
    ///
    /// # 合并策略
    ///
    /// - 值为 None 或零值时不覆盖
    /// - proxies 和 visitors 使用 extend 合并
    fn merge_client_config(target: &mut ClientConfig, source: &ClientConfig) {
        if !source.server_addr.is_empty() {
            target.server_addr = source.server_addr.clone();
        }
        if source.server_port != 0 {
            target.server_port = source.server_port;
        }
        if source.user.is_some() {
            target.user = source.user.clone();
        }
        if source.client_id.is_some() {
            target.client_id = source.client_id.clone();
        }
        target.proxies.extend(source.proxies.clone());
        target.visitors.extend(source.visitors.clone());
    }

    /// 替换字符串中的环境变量
    ///
    /// # 语法
    ///
    /// `${VAR_NAME}`
    ///
    /// # 示例
    ///
    /// ```toml
    /// server_addr = "${FRP_SERVER_ADDR}"
    /// ```
    ///
    /// 如果环境变量不存在，替换为空字符串
    fn replace_env_vars(s: &str) -> String {
        let mut result = s.to_string();
        while let Some(start) = result.find("${") {
            if let Some(end) = result[start + 2..].find('}') {
                let var_name = &result[start + 2..start + 2 + end];
                let var_value = std::env::var(var_name).unwrap_or_default();
                result.replace_range(start..start + 3 + end, &var_value);
            } else {
                break;
            }
        }
        result
    }

    /// 替换服务器配置中的环境变量
    fn replace_environment_variables(
        config: &mut ServerConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        config.bind_addr = Self::replace_env_vars(&config.bind_addr);
        if let Some(ref mut includes) = config.includes {
            for item in includes.iter_mut() {
                *item = Self::replace_env_vars(item);
            }
        }
        for proxy in config.proxies.iter_mut() {
            proxy.local_ip = Self::replace_env_vars(&proxy.local_ip);
        }
        Ok(())
    }

    /// 替换客户端配置中的环境变量
    fn replace_environment_variables_client(
        config: &mut ClientConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        config.server_addr = Self::replace_env_vars(&config.server_addr);
        if let Some(ref mut includes) = config.includes {
            for item in includes.iter_mut() {
                *item = Self::replace_env_vars(item);
            }
        }
        for proxy in config.proxies.iter_mut() {
            proxy.local_ip = Self::replace_env_vars(&proxy.local_ip);
        }
        Ok(())
    }

    /// 验证服务器配置
    ///
    /// # 必填字段
    ///
    /// - `bind_port`: 必须大于 0
    fn validate_server_config(config: &ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
        if config.bind_port == 0 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "bind_port is required",
            )));
        }
        Ok(())
    }

    /// 验证客户端配置
    ///
    /// # 必填字段
    ///
    /// - `server_addr`: 不能为空
    /// - `server_port`: 必须大于 0
    fn validate_client_config(config: &ClientConfig) -> Result<(), Box<dyn std::error::Error>> {
        if config.server_addr.is_empty() {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "server_addr is required",
            )));
        }
        if config.server_port == 0 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "server_port is required",
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_server_config() {
        let config = ServerConfig::default();
        assert_eq!(config.bind_addr, "0.0.0.0");
        assert_eq!(config.bind_port, 7000);
        assert!(config.vhost_http_port.is_none());
        assert!(config.allow_ports.is_empty());
    }

    #[test]
    fn test_default_client_config() {
        let config = ClientConfig::default();
        assert_eq!(config.server_addr, "127.0.0.1");
        assert_eq!(config.server_port, 7000);
        assert!(config.proxies.is_empty());
    }

    #[test]
    fn test_parse_config_toml() {
        let toml_str = r#"
bind_addr = "0.0.0.0"
bind_port = 9300
vhost_http_port = 8080

[auth]
method = "token"
token = "test_token"

[[allow_ports]]
single = 8080
"#;
        let config: ServerConfig = ConfigLoader::parse_config::<ServerConfig>(toml_str).unwrap();
        assert_eq!(config.bind_addr, "0.0.0.0");
        assert_eq!(config.bind_port, 9300);
        assert_eq!(config.vhost_http_port, Some(8080));
        assert_eq!(config.auth.token, Some("test_token".to_string()));
        assert_eq!(config.allow_ports.len(), 1);
        assert_eq!(config.allow_ports[0].single, Some(8080));
    }

    #[test]
    fn test_parse_config_json() {
        let json_str = r#"{
            "bind_addr": "0.0.0.0",
            "bind_port": 9300,
            "allow_ports": [{"single": 8080}]
        }"#;
        let config: ServerConfig = ConfigLoader::parse_config::<ServerConfig>(json_str).unwrap();
        assert_eq!(config.bind_port, 9300);
        assert_eq!(config.allow_ports.len(), 1);
    }

    #[test]
    fn test_validate_server_config_missing_port() {
        let config = ServerConfig {
            bind_port: 0,
            ..Default::default()
        };
        let result = ConfigLoader::validate_server_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_server_config_success() {
        let config = ServerConfig {
            bind_port: 9300,
            ..Default::default()
        };
        let result = ConfigLoader::validate_server_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_client_config_missing_addr() {
        let config = ClientConfig {
            server_addr: "".to_string(),
            ..Default::default()
        };
        let result = ConfigLoader::validate_client_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_client_config_missing_port() {
        let config = ClientConfig {
            server_port: 0,
            ..Default::default()
        };
        let result = ConfigLoader::validate_client_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_client_config_success() {
        let config = ClientConfig {
            server_addr: "example.com".to_string(),
            server_port: 9300,
            ..Default::default()
        };
        let result = ConfigLoader::validate_client_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_replace_env_vars_simple() {
        std::env::set_var("FRP_TEST_ADDR", "10.0.0.1");
        let result = ConfigLoader::replace_env_vars("${FRP_TEST_ADDR}:8080");
        assert_eq!(result, "10.0.0.1:8080");
        std::env::remove_var("FRP_TEST_ADDR");
    }

    #[test]
    fn test_replace_env_vars_not_set() {
        let result = ConfigLoader::replace_env_vars("${NONEXISTENT_VAR}");
        assert_eq!(result, "");
    }

    #[test]
    fn test_replace_env_vars_multiple() {
        std::env::set_var("HOST", "localhost");
        std::env::set_var("PORT", "9300");
        let result = ConfigLoader::replace_env_vars("${HOST}:${PORT}");
        assert_eq!(result, "localhost:9300");
        std::env::remove_var("HOST");
        std::env::remove_var("PORT");
    }

    #[test]
    fn test_port_range_single() {
        let toml_str = r#"single = 8080"#;
        let port: PortRange = toml::from_str(toml_str).unwrap();
        assert_eq!(port.single, Some(8080));
    }

    #[test]
    fn test_port_range_range() {
        let toml_str = r#"start = 10000
end = 20000"#;
        let port: PortRange = toml::from_str(toml_str).unwrap();
        assert_eq!(port.start, Some(10000));
        assert_eq!(port.end, Some(20000));
    }

    #[test]
    fn test_proxy_config_tcp() {
        let toml_str = r#"
name = "ssh"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 22
remote_port = 6000
"#;
        let proxy: ProxyConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(proxy.name, "ssh");
        assert_eq!(proxy.r#type, "tcp");
        assert_eq!(proxy.local_port, 22);
        assert_eq!(proxy.remote_port, Some(6000));
    }

    #[test]
    fn test_proxy_config_http_with_domains() {
        let toml_str = r#"
name = "web"
type = "http"
local_ip = "127.0.0.1"
local_port = 80
custom_domains = ["example.com", "www.example.com"]
"#;
        let proxy: ProxyConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(proxy.name, "web");
        assert_eq!(proxy.r#type, "http");
        assert_eq!(
            proxy.custom_domains,
            Some(vec![
                "example.com".to_string(),
                "www.example.com".to_string()
            ])
        );
    }

    #[test]
    fn test_tls_config_defaults() {
        let config = TlsConfig::default();
        assert!(config.enable);
        assert!(!config.force);
        assert!(config.cert_file.is_none());
        assert!(config.key_file.is_none());
    }

    #[test]
    fn test_transport_config_defaults() {
        let config = TransportConfig::default();
        assert_eq!(config.protocol, "tcp");
        assert!(config.tcp_mux);
        assert_eq!(config.pool_count, 10);
    }

    #[test]
    fn test_auth_config_defaults() {
        let config = AuthConfig::default();
        assert_eq!(config.method, "token");
        assert!(config.token.is_none());
    }

    #[test]
    fn test_client_config_parse() {
        let toml_str = r#"
server_addr = "10.0.0.1"
server_port = 9300

[auth]
method = "token"
token = "my_token"

[[proxies]]
name = "app1"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 8080
remote_port = 9302
"#;
        let config: ClientConfig = ConfigLoader::parse_config::<ClientConfig>(toml_str).unwrap();
        assert_eq!(config.server_addr, "10.0.0.1");
        assert_eq!(config.server_port, 9300);
        assert_eq!(config.auth.token, Some("my_token".to_string()));
        assert_eq!(config.proxies.len(), 1);
        assert_eq!(config.proxies[0].name, "app1");
    }

    #[test]
    fn test_merge_server_config() {
        let mut target = ServerConfig::default();
        let source = ServerConfig {
            bind_addr: "10.0.0.1".to_string(),
            bind_port: 9999,
            ..ServerConfig::default()
        };
        ConfigLoader::merge_server_config(&mut target, &source);
        assert_eq!(target.bind_addr, "10.0.0.1");
        assert_eq!(target.bind_port, 9999);
    }

    #[test]
    fn test_merge_client_config() {
        let mut target = ClientConfig::default();
        let source = ClientConfig {
            server_addr: "10.0.0.1".to_string(),
            server_port: 9999,
            user: Some("admin".to_string()),
            ..ClientConfig::default()
        };
        ConfigLoader::merge_client_config(&mut target, &source);
        assert_eq!(target.server_addr, "10.0.0.1");
        assert_eq!(target.server_port, 9999);
        assert_eq!(target.user, Some("admin".to_string()));
    }
}
