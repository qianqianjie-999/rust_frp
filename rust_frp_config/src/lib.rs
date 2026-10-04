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

mod compat;

use compat::ConfigKind;

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
    #[serde(alias = "bindAddr")]
    pub bind_addr: String,

    /// 控制连接端口，客户端通过此端口连接服务器
    #[serde(alias = "bindPort")]
    pub bind_port: u16,

    /// KCP 协议绑定端口（可选，UDP）
    // 路线图配置项：字段先随配置 schema 固化，协议实现后接通
    #[allow(dead_code)]
    #[serde(alias = "kcpBindPort")]
    pub kcp_bind_port: Option<u16>,

    /// QUIC 协议绑定端口（可选，UDP）
    // 路线图配置项：字段先随配置 schema 固化，协议实现后接通
    #[allow(dead_code)]
    #[serde(alias = "quicBindPort")]
    pub quic_bind_port: Option<u16>,

    /// HTTP 虚主机端口，用于 HTTP 代理
    #[serde(alias = "vhostHTTPPort")]
    pub vhost_http_port: Option<u16>,

    /// HTTPS 虚主机端口，用于 HTTPS 代理
    #[serde(alias = "vhostHTTPSPort")]
    pub vhost_https_port: Option<u16>,

    /// TCP 多路复用 HTTP 连接端口
    #[serde(alias = "tcpmuxHTTPConnectPort")]
    pub tcpmux_http_connect_port: Option<u16>,

    /// 工作连接端口，用于工作连接（默认 = bind_port + 1000）
    #[serde(alias = "workConnPort")]
    pub work_conn_port: Option<u16>,

    /// Web Dashboard 配置
    #[serde(alias = "webServer")]
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
    #[serde(alias = "allowPorts")]
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
    #[serde(alias = "maxPortsPerUser")]
    pub max_ports_per_user: Option<usize>,

    /// 自定义 404 页面路径（可选）
    #[serde(alias = "custom404Page")]
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

    /// 服务端 HTTP 插件列表（对齐原版 frp `[[httpPlugins]]`）
    ///
    /// 每配置一个插件，frps 在登录 / 代理注册 / 关闭代理 / 心跳 / 工作连接 /
    /// 用户连接等事件发生时，向该 HTTP 服务发起同步回调；回调可拒绝本次操作，
    /// 或返回修改后的内容（例如登录 metadata、代理配置）。
    ///
    /// # 配置示例
    ///
    /// ```toml
    /// [[http_plugins]]
    /// name = "user-manager"
    /// addr = "http://127.0.0.1:9000"
    /// path = "/handler"
    /// ops = ["Login", "NewProxy"]
    /// ```
    #[serde(default, alias = "httpPlugins")]
    pub http_plugins: Vec<HttpPluginConfig>,
}

/// 服务端插件支持的全部回调操作名（大小写敏感，与原版一致）。
pub const VALID_PLUGIN_OPS: &[&str] = &[
    "Login",
    "NewProxy",
    "CloseProxy",
    "Ping",
    "NewWorkConn",
    "NewUserConn",
];

/// 服务端 HTTP 插件配置项（对齐原版 frp `HTTPPluginOptions`）
///
/// # 回调协议
///
/// frps 向 `{addr}{path}?version=0.1.0&op={Op}` 发起 `POST`，请求体为
/// `{"version":"0.1.0","op":"Login","content":{...}}`，并附带 `X-Frp-Reqid` 头。
/// 插件须返回 `200` 与 JSON 响应体：
///
/// ```json
/// { "reject": false, "reject_reason": "", "unchange": true, "content": null }
/// ```
///
/// - `reject = true`：拒绝本次操作，`reject_reason` 作为错误信息回传客户端；
/// - `unchange = false`：采用响应中的 `content` 覆写原始内容
///   （仅 `Login` / `NewProxy` / `Ping` / `NewWorkConn` 支持，`CloseProxy` 忽略）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpPluginConfig {
    /// 插件名称（用于日志与错误信息）
    pub name: String,

    /// 插件 HTTP 服务地址，如 `http://127.0.0.1:9000`
    ///
    /// 未带 scheme 时按 `http://` 处理（对齐原版行为）。
    pub addr: String,

    /// 回调路径，如 `/handler`
    #[serde(default)]
    pub path: String,

    /// 订阅的操作集合
    ///
    /// 合法值：`Login` / `NewProxy` / `CloseProxy` / `Ping` / `NewWorkConn` /
    /// `NewUserConn`（大小写敏感，与原版一致）。
    pub ops: Vec<String>,

    /// 当 `addr` 为 `https://` 时是否校验服务端证书
    ///
    /// 默认 `false`（不校验），与原版 `tlsVerify` 零值语义一致。
    #[serde(default, alias = "tlsVerify")]
    pub tls_verify: bool,
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
            http_plugins: Vec::new(),
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
    #[serde(alias = "serverAddr")]
    pub server_addr: String,

    /// 服务器控制连接端口
    #[serde(alias = "serverPort")]
    pub server_port: u16,

    /// 服务器工作连接端口（可选）
    ///
    /// # 说明
    ///
    /// - 未设置时默认使用 server_port + 1000
    /// - 需与服务端 frps.toml 的 work_conn_port 一致
    #[serde(alias = "workConnPort")]
    pub work_conn_port: Option<u16>,

    /// 用户名（可选，用于多用户场景）
    pub user: Option<String>,

    /// 客户端 ID（可选，用于多客户端场景）
    #[serde(alias = "clientID")]
    pub client_id: Option<String>,

    /// Web Dashboard 配置（可选）
    #[serde(alias = "webServer")]
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

    /// 是否公开 Prometheus 抓取端点 /metrics（默认 false）
    ///
    /// 安全说明（评审 P1-4）：/metrics 包含 run_id、代理名、流量计数等
    /// 内部信息。默认关闭（请求返回 404）；需要 Prometheus 抓取时显式
    /// 置为 true，并建议同时用反向代理限制来源。
    #[serde(default, alias = "exposeMetrics")]
    pub expose_metrics: bool,
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
/// 客户端与服务端共用同一结构：服务端用 `issuer`（发现 + JWKS 验签），
/// 客户端用 `client_id` / `client_secret` / `token_endpoint_url`（取令牌）。
///
/// # 服务端（`issuer` 侧）
///
/// - `issuer`：用于拉取 `{issuer}/.well-known/openid-configuration` 并比对 `iss` 声明
/// - `audience`：为空时跳过 `aud` 校验
/// - `skip_issuer_check` / `skip_expiry_check`：分别跳过 `iss` / `exp` 校验
///
/// # 客户端（取令牌侧）
///
/// - `client_id` / `client_secret`：`client_credentials` 凭据
/// - `token_endpoint_url`：令牌端点
/// - `scope` / `additional_endpoint_params`：附加的授权范围与端点参数
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(default)]
pub struct OidcConfig {
    /// 发行者 URL（服务端必填；客户端可选，仅用于比对 `iss`）
    pub issuer: String,

    /// 受众（token 的 `aud` 声明；为空时服务端跳过校验）
    pub audience: String,

    /// OAuth 客户端 ID
    #[serde(alias = "clientID")]
    pub client_id: String,

    /// OAuth 客户端密钥
    #[serde(alias = "clientSecret")]
    pub client_secret: String,

    /// Token 端点 URL
    #[serde(alias = "tokenEndpointURL")]
    pub token_endpoint_url: String,

    /// 请求令牌时申请的授权范围（`scope`）
    pub scope: String,

    /// 请求令牌时附加的端点参数（如 `resource`、`audience`）
    #[serde(alias = "additionalEndpointParams")]
    pub additional_endpoint_params: std::collections::HashMap<String, String>,

    /// 校验 OIDC 端点 TLS 证书所用的根 CA 文件
    #[serde(alias = "trustedCaFile")]
    pub trusted_ca_file: String,

    /// 是否跳过 OIDC 端点的证书校验（**仅调试用**）
    #[serde(alias = "insecureSkipVerify")]
    pub insecure_skip_verify: bool,

    /// 服务端：是否跳过 token 过期时间（`exp`）校验
    #[serde(alias = "skipExpiryCheck")]
    pub skip_expiry_check: bool,

    /// 服务端：是否跳过 token 发行者（`iss`）校验
    #[serde(alias = "skipIssuerCheck")]
    pub skip_issuer_check: bool,
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
    #[serde(alias = "tcpMux")]
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
    #[serde(alias = "tlsOnly")]
    pub tls_only: bool,

    /// 连接池大小
    ///
    /// 客户端预建立的工作连接数量。建议值：5-100
    #[serde(alias = "poolCount")]
    pub pool_count: u32,

    /// 带宽限制（可选），格式如 "1MB" 或 "1GB"
    #[serde(alias = "bandwidthLimit")]
    pub bandwidth_limit: Option<String>,

    /// 应用层加密开关（兼容原版 `transport.useEncryption`）
    ///
    /// # 说明
    ///
    /// 仅在代理/访问者级 `[[proxies]].transport` 子表中生效：解析后会被
    /// 合并进该代理的 `use_encryption`（见 ConfigLoader 的 normalize 步骤）。
    /// 出现在全局 `[transport]` 中时被忽略。
    #[serde(default, alias = "useEncryption")]
    pub use_encryption: bool,

    /// 应用层压缩（兼容原版 `transport.useCompression`）
    ///
    /// 仅在代理/访问者级 `[[proxies]].transport` 子表中生效：解析后会被
    /// 合并进该代理的 `use_compression`（见 ConfigLoader 的 normalize 步骤）。
    /// 出现在全局 `[transport]` 中时被忽略。
    #[serde(default, alias = "useCompression")]
    pub use_compression: bool,

    /// 带宽限制模式（兼容原版 `transport.bandwidthLimitMode`，"client"/"server"）
    ///
    // 路线图配置项：仅 client 模式实际生效，server 模式未实现。
    #[serde(default, alias = "bandwidthLimitMode")]
    #[allow(dead_code)]
    pub bandwidth_limit_mode: Option<String>,

    /// PROXY protocol 版本（兼容原版 `transport.proxyProtocolVersion`，"v1"/"v2"）
    ///
    // 路线图配置项：本实现仅支持 v1（proxy_protocol 布尔开关），v2 未实现。
    #[serde(default, alias = "proxyProtocolVersion")]
    #[allow(dead_code)]
    pub proxy_protocol_version: Option<String>,
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
            use_encryption: false,
            use_compression: false,
            bandwidth_limit_mode: None,
            proxy_protocol_version: None,
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
    #[serde(alias = "certFile")]
    pub cert_file: Option<String>,

    /// TLS 私钥文件路径（服务器用）
    #[serde(alias = "keyFile")]
    pub key_file: Option<String>,

    /// 受信任的 CA 证书文件路径（客户端用）
    ///
    /// 用于验证服务器证书
    #[serde(alias = "trustedCaFile")]
    pub trusted_ca_file: Option<String>,

    /// 是否跳过服务器证书验证（客户端用）
    ///
    /// 适用于使用自定义自签名证书的场景，仅加密连接，不验证证书
    ///
    /// # 默认值
    ///
    /// **false** - 默认验证服务器证书
    #[serde(alias = "skipVerify")]
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
/// - `type`: 代理类型 (tcp/udp/http/https/websocket/stcp/xtcp/tcpmux/sudp)
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
    /// - `websocket`: WebSocket 代理
    /// - `stcp`: 秘密 TCP（需要访问密钥）
    /// - `xtcp`: P2P TCP
    /// - `tcpmux`: HTTP CONNECT 复用的 TCP 代理（按域名路由）
    /// - `sudp`: 秘密 UDP（经 STCP 隧道承载 UDP，需要访问密钥）
    #[serde(rename = "type")]
    pub r#type: String,

    /// 本地服务 IP 地址
    #[serde(alias = "localIP")]
    pub local_ip: String,

    /// 本地服务端口
    #[serde(alias = "localPort")]
    pub local_port: u16,

    /// 远程映射端口（TCP/UDP 代理必需）
    #[serde(alias = "remotePort")]
    pub remote_port: Option<u16>,

    /// 自定义域名列表（HTTP/HTTPS 代理用）
    ///
    /// # 示例
    ///
    /// ```toml
    /// custom_domains = ["web.example.com", "api.example.com"]
    /// ```
    #[serde(alias = "customDomains")]
    pub custom_domains: Option<Vec<String>>,

    /// 子域名（HTTP/HTTPS 代理用）
    ///
    /// 配合服务器的 `subdomain_base` 使用
    #[serde(alias = "subDomain")]
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
    #[serde(alias = "hostHeaderRewrite")]
    pub host_header_rewrite: Option<String>,

    /// HTTP 基本认证用户名（HTTP 代理用）
    #[serde(alias = "httpUser")]
    pub http_user: Option<String>,

    /// HTTP 基本认证密码（HTTP 代理用）
    #[serde(alias = "httpPassword")]
    pub http_password: Option<String>,

    /// 健康检查配置（可选）
    #[serde(alias = "healthCheck")]
    pub health_check: Option<HealthCheckConfig>,

    /// 带宽限制（可选），格式如 "1MB"、"500KB"、"10GB"
    ///
    /// 限制该代理的最大传输速率，覆盖全局 bandwidth_limit
    #[serde(alias = "bandwidthLimit")]
    pub bandwidth_limit: Option<String>,

    /// 共享密钥（stcp/xtcp 代理用）
    #[serde(alias = "secretKey")]
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
    #[serde(alias = "proxyProtocol")]
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
    #[serde(alias = "groupKey")]
    pub group_key: Option<String>,

    /// 应用层加密：对该代理的工作连接流量启用 AES-256-GCM 加密
    ///
    /// 密钥由 token 派生（SHA-256），两端需配置一致；只加密不认证，
    /// 防被动嗅探不防中间人（需要身份认证请叠加 TLS）。
    /// 客户端未配置 token 时启用此选项会导致代理启动失败（fail-closed）。
    #[serde(default, alias = "useEncryption")]
    pub use_encryption: bool,

    /// 应用层压缩：对该代理的工作连接流量启用 snappy 压缩
    ///
    /// 两端需配置一致（对端关闭压缩时收到压缩帧会立即断连）；
    /// 与 `use_encryption` 可叠加，顺序固定为「先压缩、后加密」。
    #[serde(default, alias = "useCompression")]
    pub use_compression: bool,

    /// tcpmux 复用器类型（仅 `type = "tcpmux"` 使用）
    ///
    /// 目前仅支持 `"httpconnect"`（缺省即 httpconnect）。服务器据此在
    /// `tcpmux_http_connect_port` 上解析 HTTP CONNECT 请求并按域名路由。
    #[serde(alias = "multiplexer")]
    pub multiplexer: Option<String>,

    /// 按 HTTP 用户路由（仅 tcpmux，可选）
    ///
    /// 设置后仅当 CONNECT 请求的 `Proxy-Authorization` 用户名为该值时
    /// 才匹配本代理，用于同一域名下按用户区分多个 tcpmux 代理。
    #[serde(alias = "routeByHTTPUser")]
    pub route_by_http_user: Option<String>,

    /// 允许访问的客户端用户列表（stcp/xtcp/sudp 代理，可选）
    ///
    /// 为空表示不限；非空时仅列表中用户的访问者可以连接本代理。
    #[serde(alias = "allowUsers")]
    pub allow_users: Option<Vec<String>>,
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
    #[serde(alias = "serverName")]
    pub server_name: String,

    /// 共享密钥（需与对方代理配置匹配）
    #[serde(alias = "secretKey")]
    pub secret_key: Option<String>,

    /// 本地绑定地址
    #[serde(alias = "bindAddr")]
    pub bind_addr: String,

    /// 本地监听端口
    ///
    /// 访问者连接此端口即可访问远程服务
    #[serde(alias = "bindPort")]
    pub bind_port: u16,

    /// 传输层配置（可选）
    pub transport: Option<TransportConfig>,

    /// 应用层加密：需与对端代理的 use_encryption 配置一致
    #[serde(default, alias = "useEncryption")]
    pub use_encryption: bool,

    /// 应用层压缩：需与对端代理的 use_compression 配置一致
    #[serde(default, alias = "useCompression")]
    pub use_compression: bool,
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
    #[serde(alias = "timeoutSeconds")]
    pub timeout_seconds: u32,

    /// 连续失败次数阈值
    ///
    /// 超过此值则判定为不健康
    #[serde(alias = "maxFailed")]
    pub max_failed: u32,

    /// 检查间隔（秒）
    #[serde(alias = "intervalSeconds")]
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
    #[serde(alias = "unixPath")]
    pub unix_path: Option<String>,

    /// 本地文件路径（static_file 插件用）
    #[serde(alias = "localPath")]
    pub local_path: Option<String>,

    /// 路径前缀剥离（static_file 插件用）
    #[serde(alias = "stripPrefix")]
    pub strip_prefix: Option<String>,

    /// HTTP 用户名（http_proxy 插件用）
    #[serde(alias = "httpUser")]
    pub http_user: Option<String>,

    /// HTTP 密码（http_proxy 插件用）
    #[serde(alias = "httpPassword")]
    pub http_password: Option<String>,

    /// 本地地址（http_proxy/socks5 及 TLS 系插件 https2http/tls2raw/https2https 用）
    #[serde(alias = "localAddr")]
    pub local_addr: Option<String>,

    /// 证书文件路径（HTTPS 相关插件用）
    #[serde(alias = "crtPath")]
    pub crt_path: Option<String>,

    /// 私钥文件路径（HTTPS 相关插件用）
    #[serde(alias = "keyPath")]
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
        let mut config: ServerConfig = Self::load_config_from_file(path, ConfigKind::Server)?;
        Self::process_includes(&mut config)?;
        Self::replace_environment_variables(&mut config)?;
        Self::normalize_server_config(&mut config);
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
        let mut config = Self::load_config_from_file(path, ConfigKind::Client)?;
        Self::process_includes_client(&mut config)?;
        Self::replace_environment_variables_client(&mut config)?;
        Self::normalize_client_config(&mut config);
        Self::validate_client_config(&config)?;
        Ok(config)
    }

    /// 校验配置内容（不读文件、不落盘）
    ///
    /// 供客户端管理 API（`PUT /config`）使用：完整走「解析 → 归并 → 校验」
    /// 链路，任何一步失败都返回 Err。注意不处理 `includes`（相对路径解析
    /// 依赖配置文件所在目录，留待随后的 reload 从磁盘加载时处理）。
    pub fn validate_client_config_content(
        content: &str,
    ) -> Result<ClientConfig, Box<dyn std::error::Error>> {
        let mut config = Self::parse_config::<ClientConfig>(content, ConfigKind::Client)?;
        Self::normalize_client_config(&mut config);
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
        kind: ConfigKind,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let mut file = File::open(path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        // 注意：绝不能把配置原文写进日志——配置文件里通常包含 auth token、
        // web_server 密码、OIDC client_secret 等敏感信息。
        log::debug!("Loaded config content ({} bytes)", content.len());
        Self::parse_config(&content, kind)
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
        kind: ConfigKind,
    ) -> Result<T, Box<dyn std::error::Error>> {
        // 按 TOML -> YAML -> JSON 顺序盲试；全部失败时把三种格式各自的
        // 错误信息汇总后抛出，避免排障时只能看到一句无信息量的
        // "Failed to parse config file"。
        let mut errors: Vec<String> = Vec::new();

        log::info!("Trying to parse config as TOML");
        match toml::from_str::<T>(content) {
            Ok(config) => {
                log::info!("Successfully parsed config as TOML");
                Self::warn_raw_fields::<toml::Value>(content, kind);
                return Ok(config);
            }
            Err(e) => {
                log::debug!("Failed to parse as TOML: {}", e);
                errors.push(format!("TOML: {}", e));
            }
        }

        log::info!("Trying to parse config as YAML");
        match serde_yaml::from_str::<T>(content) {
            Ok(config) => {
                log::info!("Successfully parsed config as YAML");
                Self::warn_raw_fields::<serde_yaml::Value>(content, kind);
                return Ok(config);
            }
            Err(e) => {
                log::debug!("Failed to parse as YAML: {}", e);
                errors.push(format!("YAML: {}", e));
            }
        }

        log::info!("Trying to parse config as JSON");
        match serde_json::from_str::<T>(content) {
            Ok(config) => {
                log::info!("Successfully parsed config as JSON");
                Self::warn_raw_fields::<serde_json::Value>(content, kind);
                return Ok(config);
            }
            Err(e) => {
                log::debug!("Failed to parse as JSON: {}", e);
                errors.push(format!("JSON: {}", e));
            }
        }

        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Failed to parse config file; attempted TOML/YAML/JSON, all failed:\n  {}",
                errors.join("\n  ")
            ),
        )))
    }

    /// 把原始配置文本转成 JSON Value 后做未知字段告警。
    ///
    /// 解析失败时静默跳过（主解析已报错，告警无意义）。
    fn warn_raw_fields<R: serde::de::DeserializeOwned + serde::Serialize>(
        content: &str,
        kind: ConfigKind,
    ) {
        let Ok(raw) = serde_json::from_str::<R>(content) else {
            return;
        };
        let Ok(json) = serde_json::to_value(&raw) else {
            return;
        };
        compat::warn_unknown_fields(kind, &json);
    }

    /// 归并代理级 transport 子表中的应用层加密开关。
    ///
    /// 原版 frp 把 `useEncryption` 放在 `[[proxies]].transport` 子表中，
    /// 本实现的主开关在代理顶层 `use_encryption`；两者任一为 true 即生效。
    fn normalize_server_config(config: &mut ServerConfig) {
        for proxy in &mut config.proxies {
            if let Some(t) = &proxy.transport {
                if t.use_encryption {
                    proxy.use_encryption = true;
                }
            }
        }
    }

    /// 客户端版归并：除代理外还处理 `[[visitors]].transport.useEncryption`
    fn normalize_client_config(config: &mut ClientConfig) {
        for proxy in &mut config.proxies {
            if let Some(t) = &proxy.transport {
                if t.use_encryption {
                    proxy.use_encryption = true;
                }
                if t.use_compression {
                    proxy.use_compression = true;
                }
            }
        }
        for visitor in &mut config.visitors {
            if let Some(t) = &visitor.transport {
                if t.use_encryption {
                    visitor.use_encryption = true;
                }
                if t.use_compression {
                    visitor.use_compression = true;
                }
            }
        }
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
                            let include_config =
                                Self::load_config_from_file(path, ConfigKind::Server)?;
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
                            let include_config =
                                Self::load_config_from_file(path, ConfigKind::Client)?;
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

        // Web 管理端凭据必须成对配置：只填一半会导致鉴权被静默关闭，
        // dashboard 直接对全网暴露，因此这里直接拒绝启动。
        let web = &config.web_server;
        if web.port != 0 {
            match (&web.user, &web.password) {
                (Some(user), Some(password)) => {
                    if user.is_empty() || password.is_empty() {
                        return Err(Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "web_server.user and web_server.password must be non-empty \
                             (an empty credential would disable dashboard authentication)",
                        )));
                    }
                    if user == "admin" && password == "admin" {
                        log::warn!(
                            "web_server is using the default admin/admin credentials; \
                             change them before exposing the dashboard"
                        );
                    }
                }
                (None, None) => {
                    log::warn!(
                        "web_server.user/password not configured: dashboard authentication \
                         is DISABLED, anyone who can reach the port can read the dashboard"
                    );
                }
                _ => {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "web_server.user and web_server.password must be configured together",
                    )));
                }
            }
        }

        // 服务端 HTTP 插件：name/addr/ops 必须有效，op 必须是已知回调类型。
        // 非法配置直接拒绝启动，避免「配了插件却静默不回调」。
        for (i, plugin) in config.http_plugins.iter().enumerate() {
            if plugin.name.trim().is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("http_plugins[{i}].name must be non-empty"),
                )));
            }
            if plugin.addr.trim().is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("http_plugins[{i}].addr must be non-empty"),
                )));
            }
            if plugin.ops.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "http_plugins[{i}] ({}) subscribes to no operation; \
                         ops must list at least one of {VALID_PLUGIN_OPS:?}",
                        plugin.name
                    ),
                )));
            }
            for op in &plugin.ops {
                if !VALID_PLUGIN_OPS.contains(&op.as_str()) {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "http_plugins[{i}] ({}) has unknown op {:?}; valid ops are {VALID_PLUGIN_OPS:?}",
                            plugin.name, op
                        ),
                    )));
                }
            }
        }

        // OIDC：服务端必须配置 issuer —— 它是发现文档与 JWKS 的入口，
        // 缺失会导致「配了 oidc 却无法验签」。鉴权方法本身也要合法。
        match config.auth.method.as_str() {
            "token" => {}
            "oidc" => {
                let Some(oidc) = config.auth.oidc.as_ref() else {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "auth.oidc is required when auth.method = \"oidc\"",
                    )));
                };
                if oidc.issuer.trim().is_empty() {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "auth.oidc.issuer is required for server-side OIDC token verification",
                    )));
                }
            }
            other => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("unsupported auth.method: {other} (expected \"token\" or \"oidc\")"),
                )));
            }
        }

        Ok(())
    }

    /// 校验一个绝对的 http/https URL（含非空 host）
    fn validate_absolute_http_url(
        value: &str,
        field: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for scheme in ["http://", "https://"] {
            if let Some(rest) = value.strip_prefix(scheme) {
                let host = rest.split(['/', '?', '#']).next().unwrap_or("");
                if !host.is_empty() {
                    return Ok(());
                }
            }
        }
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{field} = \"{value}\" must be an absolute http or https URL"),
        )))
    }

    /// 校验带宽限制字符串
    ///
    /// 支持 `"1GB"` / `"10MB"` / `"500KB"` / `"1024B"` / `"1024"`（纯字节数）。
    /// 非法值（空串、非数字、`0`、负数）一律报错——避免出现「配置里写了限速，
    /// 运行期却被静默忽略」的情况。
    fn validate_bandwidth_limit(
        value: &str,
        field: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let upper = value.trim().to_uppercase();
        let num_part = if let Some(n) = upper.strip_suffix("GB") {
            n.trim()
        } else if let Some(n) = upper.strip_suffix("MB") {
            n.trim()
        } else if let Some(n) = upper.strip_suffix("KB") {
            n.trim()
        } else if let Some(n) = upper.strip_suffix('B') {
            n.trim()
        } else {
            upper.as_str()
        };

        let valid = num_part
            .parse::<f64>()
            .map(|v| v.is_finite() && v > 0.0)
            .unwrap_or(false);

        if valid {
            Ok(())
        } else {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "{} = \"{}\" is invalid; expected a positive value such as \
                     \"1GB\", \"10MB\", \"500KB\" or a plain number of bytes",
                    field, value
                ),
            )))
        }
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

        // 带宽限制：非法值直接报错，而不是运行期被静默丢弃
        if let Some(limit) = &config.transport.bandwidth_limit {
            Self::validate_bandwidth_limit(limit, "transport.bandwidth_limit")?;
        }
        for proxy in &config.proxies {
            if let Some(limit) = &proxy.bandwidth_limit {
                Self::validate_bandwidth_limit(
                    limit,
                    &format!("proxies[name={}].bandwidth_limit", proxy.name),
                )?;
            }

            // tcpmux：仅支持 httpconnect 复用器，且必须配置域名（服务器按域名路由）
            if proxy.r#type == "tcpmux" {
                if let Some(multiplexer) = proxy.multiplexer.as_deref() {
                    if !multiplexer.is_empty() && multiplexer != "httpconnect" {
                        return Err(Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "proxies[name={}].multiplexer [{}] is not supported (only \"httpconnect\")",
                                proxy.name, multiplexer
                            ),
                        )));
                    }
                }
                let has_domain = proxy
                    .custom_domains
                    .as_ref()
                    .is_some_and(|domains| domains.iter().any(|d| !d.is_empty()))
                    || proxy.subdomain.as_deref().is_some_and(|s| !s.is_empty());
                if !has_domain {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "proxies[name={}] is a tcpmux proxy and requires custom_domains or subdomain",
                            proxy.name
                        ),
                    )));
                }
            }
        }

        // OIDC 客户端：client_credentials 需要 client_id 与绝对 http(s) 的令牌端点。
        match config.auth.method.as_str() {
            "token" => {}
            "oidc" => {
                let Some(oidc) = config.auth.oidc.as_ref() else {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "auth.oidc is required when auth.method = \"oidc\"",
                    )));
                };
                if oidc.client_id.trim().is_empty() {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "auth.oidc.client_id is required for OIDC client credentials",
                    )));
                }
                Self::validate_absolute_http_url(
                    oidc.token_endpoint_url.trim(),
                    "auth.oidc.token_endpoint_url",
                )?;
                if oidc.additional_endpoint_params.contains_key("scope") {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "auth.oidc.additional_endpoint_params.scope is not allowed; \
                         use auth.oidc.scope instead",
                    )));
                }
                if !oidc.audience.is_empty()
                    && oidc.additional_endpoint_params.contains_key("audience")
                {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "cannot specify both auth.oidc.audience and \
                         auth.oidc.additional_endpoint_params.audience",
                    )));
                }
            }
            other => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("unsupported auth.method: {other} (expected \"token\" or \"oidc\")"),
                )));
            }
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
        let config: ServerConfig =
            ConfigLoader::parse_config::<ServerConfig>(toml_str, ConfigKind::Server).unwrap();
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
        let config: ServerConfig =
            ConfigLoader::parse_config::<ServerConfig>(json_str, ConfigKind::Server).unwrap();
        assert_eq!(config.bind_port, 9300);
        assert_eq!(config.allow_ports.len(), 1);
    }

    #[test]
    fn test_parse_tcpmux_and_sudp_proxy_fields() {
        let toml_str = r#"
server_addr = "127.0.0.1"
server_port = 7000

[[proxies]]
name = "mux"
type = "tcpmux"
custom_domains = ["mux.example.com"]
multiplexer = "httpconnect"
routeByHTTPUser = "alice"
httpUser = "alice"
httpPassword = "pw"
allowUsers = ["alice", "bob"]
useCompression = true

[[visitors]]
name = "visit-udp"
type = "sudp"
server_name = "udp-svc"
bind_addr = "127.0.0.1"
bind_port = 5353
secret_key = "s3cret"
useCompression = true
"#;
        let config: ClientConfig =
            ConfigLoader::parse_config::<ClientConfig>(toml_str, ConfigKind::Client).unwrap();

        let proxy = &config.proxies[0];
        assert_eq!(proxy.r#type, "tcpmux");
        assert_eq!(proxy.multiplexer.as_deref(), Some("httpconnect"));
        assert_eq!(proxy.route_by_http_user.as_deref(), Some("alice"));
        assert_eq!(
            proxy.allow_users.as_deref(),
            Some(["alice".to_string(), "bob".to_string()].as_slice())
        );
        assert!(proxy.use_compression);

        let visitor = &config.visitors[0];
        assert_eq!(visitor.r#type, "sudp");
        assert_eq!(visitor.secret_key.as_deref(), Some("s3cret"));
        assert!(visitor.use_compression);
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
        let config: ClientConfig =
            ConfigLoader::parse_config::<ClientConfig>(toml_str, ConfigKind::Client).unwrap();
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

    #[test]
    fn test_web_server_expose_metrics_defaults_to_false() {
        // 安全默认：未配置 expose_metrics 时必须关闭 /metrics（P1-4）
        let config: WebServerConfig = toml::from_str(
            r#"
addr = "127.0.0.1"
port = 7500
user = "boss"
password = "pw"
"#,
        )
        .unwrap();
        assert!(!config.expose_metrics);
    }

    #[test]
    fn test_web_server_expose_metrics_can_be_enabled() {
        let config: WebServerConfig = toml::from_str(
            r#"
addr = "127.0.0.1"
port = 7500
expose_metrics = true
"#,
        )
        .unwrap();
        assert!(config.expose_metrics);
    }
}

#[cfg(test)]
mod example_config_tests {
    use super::ConfigLoader;
    use std::path::Path;
    /// 示例配置文件必须始终可解析：README 引导用户复制 example 改配置，
    /// 若字段重命名/删除后未同步 example，用户会拿到一个跑不起来的模板。
    #[test]
    fn test_frpc_example_toml_always_parses() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../frpc.example.toml");
        let config = ConfigLoader::load_client_config(&path)
            .expect("frpc.example.toml must stay parseable by ConfigLoader");
        assert!(!config.server_addr.is_empty());
        assert!(config.server_port > 0);
    }

    #[test]
    fn test_frps_example_toml_always_parses() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../frps.example.toml");
        let config = ConfigLoader::load_server_config(&path)
            .expect("frps.example.toml must stay parseable by ConfigLoader");
        assert!(config.bind_port > 0);
    }
}

#[cfg(test)]
mod upstream_compat_tests {
    use super::ConfigLoader;
    use std::path::PathBuf;

    /// 把内容写成临时 TOML 并加载（走完整 load 链路：解析→includes→环境变量→归并→验证）
    fn write_temp_config(prefix: &str, content: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "{}_{}_{}.toml",
            prefix,
            std::process::id(),
            super::compat_test_counter()
        ));
        std::fs::write(&path, content).expect("write temp config");
        path
    }

    /// 服务端 [[httpPlugins]]（原版 camelCase 数组表）必须可解析并落到 http_plugins。
    #[test]
    fn test_upstream_http_plugins_config_parses() {
        let path = write_temp_config(
            "frps_plugins",
            r#"
bindAddr = "0.0.0.0"
bindPort = 7000

[[httpPlugins]]
name = "user-manager"
addr = "http://127.0.0.1:9000"
path = "/handler"
ops = ["Login", "NewProxy"]
tlsVerify = false
"#,
        );
        let config = ConfigLoader::load_server_config(&path).expect("httpPlugins must parse");
        assert_eq!(config.http_plugins.len(), 1);
        let plugin = &config.http_plugins[0];
        assert_eq!(plugin.name, "user-manager");
        assert_eq!(plugin.addr, "http://127.0.0.1:9000");
        assert_eq!(plugin.path, "/handler");
        assert_eq!(
            plugin.ops,
            vec!["Login".to_string(), "NewProxy".to_string()]
        );
        assert!(!plugin.tls_verify);
        let _ = std::fs::remove_file(&path);
    }

    /// 未知 op 的插件必须被拒绝（避免「配了插件却静默不回调」）。
    #[test]
    fn test_http_plugins_unknown_op_rejected() {
        let path = write_temp_config(
            "frps_bad_plugin",
            r#"
bindAddr = "0.0.0.0"
bindPort = 7000

[[http_plugins]]
name = "bad"
addr = "http://127.0.0.1:9000"
ops = ["Login", "NotAnOp"]
"#,
        );
        let err = ConfigLoader::load_server_config(&path).unwrap_err();
        assert!(
            err.to_string().contains("unknown op"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// 服务端 [[http_plugins]]（canonical snake_case）同样可解析，
    /// 且不得被未知字段检查误报（compat 已知键集回归）。
    #[test]
    fn test_snake_case_http_plugins_config_parses() {
        let path = write_temp_config(
            "frps_plugins_snake",
            r#"
bindAddr = "0.0.0.0"
bindPort = 7000

[[http_plugins]]
name = "local"
addr = "http://127.0.0.1:9100"
ops = ["Login"]

[webServer]
port = 7500
user = "admin"
password = "pw"
"#,
        );
        let config = ConfigLoader::load_server_config(&path).expect("http_plugins must parse");
        assert_eq!(config.http_plugins.len(), 1);
        assert_eq!(config.http_plugins[0].name, "local");
        let _ = std::fs::remove_file(&path);
    }

    /// 客户端 OIDC：原版 camelCase 字段（clientID/clientSecret/tokenEndpointURL）
    /// 与新增字段（scope/additionalEndpointParams/trustedCaFile/insecureSkipVerify）
    /// 必须全部正确落到配置结构。
    #[test]
    fn test_upstream_oidc_client_config_parses() {
        let path = write_temp_config(
            "frpc_oidc",
            r#"
serverAddr = "203.0.113.10"
serverPort = 7000

[auth]
method = "oidc"

[auth.oidc]
issuer = "https://idp.example.com"
audience = "frp-server"
clientID = "frp-client"
clientSecret = "s3cret"
tokenEndpointURL = "https://idp.example.com/token"
scope = "openid profile"
trustedCaFile = "/etc/ssl/idp-ca.pem"
insecureSkipVerify = true

[auth.oidc.additionalEndpointParams]
resource = "https://api.example.com"
"#,
        );
        let config = ConfigLoader::load_client_config(&path).expect("oidc config must parse");
        let oidc = config.auth.oidc.as_ref().expect("oidc present");
        assert_eq!(config.auth.method, "oidc");
        assert_eq!(oidc.client_id, "frp-client");
        assert_eq!(oidc.client_secret, "s3cret");
        assert_eq!(oidc.token_endpoint_url, "https://idp.example.com/token");
        assert_eq!(oidc.scope, "openid profile");
        assert_eq!(oidc.trusted_ca_file, "/etc/ssl/idp-ca.pem");
        assert!(oidc.insecure_skip_verify);
        assert_eq!(
            oidc.additional_endpoint_params
                .get("resource")
                .map(String::as_str),
            Some("https://api.example.com")
        );
        let _ = std::fs::remove_file(&path);
    }

    /// 服务端 OIDC：必须配置 issuer，否则启动即失败；配了则解析出 skip* 开关。
    #[test]
    fn test_server_oidc_requires_issuer() {
        let path = write_temp_config(
            "frps_oidc_missing_issuer",
            r#"
bindAddr = "0.0.0.0"
bindPort = 7000

[auth]
method = "oidc"

[auth.oidc]
audience = "frp-server"
"#,
        );
        let err = ConfigLoader::load_server_config(&path).unwrap_err();
        assert!(err.to_string().contains("issuer"), "unexpected: {err}");
        let _ = std::fs::remove_file(&path);

        let path = write_temp_config(
            "frps_oidc_no_config",
            r#"
bindAddr = "0.0.0.0"
bindPort = 7000

[auth]
method = "oidc"
"#,
        );
        let err = ConfigLoader::load_server_config(&path).unwrap_err();
        assert!(err.to_string().contains("auth.oidc"), "unexpected: {err}");
        let _ = std::fs::remove_file(&path);

        let path = write_temp_config(
            "frps_oidc_ok",
            r#"
bindAddr = "0.0.0.0"
bindPort = 7000

[auth]
method = "oidc"

[auth.oidc]
issuer = "https://idp.example.com"
audience = "frp-server"
skipExpiryCheck = true
skipIssuerCheck = false
"#,
        );
        let config = ConfigLoader::load_server_config(&path).expect("server oidc must parse");
        let oidc = config.auth.oidc.expect("oidc present");
        assert_eq!(oidc.issuer, "https://idp.example.com");
        assert!(oidc.skip_expiry_check);
        assert!(!oidc.skip_issuer_check);
        let _ = std::fs::remove_file(&path);
    }

    /// 客户端 OIDC 的非法配置必须被拒绝：缺 client_id、端点 URL 非绝对 http(s)、
    /// 以及 additionalEndpointParams 里塞 scope。
    #[test]
    fn test_client_oidc_validation_errors() {
        let cases = [
            (
                "frpc_oidc_no_client",
                "[auth.oidc]\ntokenEndpointURL = \"https://idp.example.com/token\"\n",
                "client_id",
            ),
            (
                "frpc_oidc_bad_url",
                "[auth.oidc]\nclientID = \"c\"\ntokenEndpointURL = \"idp.example.com/token\"\n",
                "absolute http",
            ),
            (
                "frpc_oidc_scope_param",
                "[auth.oidc]\nclientID = \"c\"\ntokenEndpointURL = \"https://idp.example.com/token\"\n\
                 \n[auth.oidc.additionalEndpointParams]\nscope = \"openid\"\n",
                "additional_endpoint_params.scope",
            ),
        ];
        for (name, tail, needle) in cases {
            let content = format!("serverAddr = \"1.2.3.4\"\nserverPort = 7000\n\n[auth]\nmethod = \"oidc\"\n\n{tail}");
            let path = write_temp_config(name, &content);
            let err = ConfigLoader::load_client_config(&path).unwrap_err();
            assert!(
                err.to_string().contains(needle),
                "case {name}: expected {needle:?}, got {err}"
            );
            let _ = std::fs::remove_file(&path);
        }
    }

    /// 未知的 auth.method 必须被拒绝（避免「配了个不认识的方法却静默放行」）。
    #[test]
    fn test_unsupported_auth_method_rejected() {
        let path = write_temp_config(
            "frps_bad_auth",
            r#"
bindAddr = "0.0.0.0"
bindPort = 7000

[auth]
method = "ldap"
"#,
        );
        let err = ConfigLoader::load_server_config(&path).unwrap_err();
        assert!(
            err.to_string().contains("unsupported auth.method"),
            "unexpected: {err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// 原版 frp 0.71 风格的客户端配置（camelCase + transport.useEncryption 嵌套）
    /// 必须可以直接解析，且语义与本项目的 snake_case 写法一致。
    #[test]
    fn test_upstream_camelcase_client_config_parses() {
        let path = write_temp_config(
            "frpc_upstream",
            r#"
serverAddr = "203.0.113.10"
serverPort = 7000
user = "alice"

auth.method = "token"
auth.token = "shared-secret"

transport.protocol = "tcp"
transport.tls.enable = true
transport.poolCount = 6

[[proxies]]
name = "ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6022

[[proxies]]
name = "web-encrypted"
type = "tcp"
localIP = "127.0.0.1"
localPort = 8080
remotePort = 6180
transport.useEncryption = true

[[visitors]]
name = "visit-ssh"
type = "stcp"
serverName = "peer-ssh"
secretKey = "peer-key"
bindAddr = "127.0.0.1"
bindPort = 9000
"#,
        );
        let config =
            ConfigLoader::load_client_config(&path).expect("upstream-style frpc config must parse");
        std::fs::remove_file(&path).ok();

        assert_eq!(config.server_addr, "203.0.113.10");
        assert_eq!(config.server_port, 7000);
        assert_eq!(config.user.as_deref(), Some("alice"));
        assert_eq!(config.auth.token.as_deref(), Some("shared-secret"));
        assert_eq!(config.transport.pool_count, 6);

        assert_eq!(config.proxies[0].local_ip, "127.0.0.1");
        assert_eq!(config.proxies[0].remote_port, Some(6022));
        assert!(!config.proxies[0].use_encryption);

        // transport.useEncryption 应被归并进代理顶层 use_encryption
        assert!(config.proxies[1].use_encryption);

        assert_eq!(config.visitors[0].server_name, "peer-ssh");
        assert_eq!(config.visitors[0].bind_port, 9000);
    }

    /// 原版风格的服务端配置
    #[test]
    fn test_upstream_camelcase_server_config_parses() {
        let path = write_temp_config(
            "frps_upstream",
            r#"
bindAddr = "0.0.0.0"
bindPort = 7000
vhostHTTPPort = 8080
vhostHTTPSPort = 8443
workConnPort = 8000

webServer.port = 7500
webServer.addr = "127.0.0.1"
webServer.user = "admin"
webServer.password = "admin-pwd"

transport.tls.force = true

[[allowPorts]]
start = 10000
end = 20000
"#,
        );
        let config =
            ConfigLoader::load_server_config(&path).expect("upstream-style frps config must parse");
        std::fs::remove_file(&path).ok();

        assert_eq!(config.bind_port, 7000);
        assert_eq!(config.vhost_http_port, Some(8080));
        assert_eq!(config.vhost_https_port, Some(8443));
        assert_eq!(config.work_conn_port, Some(8000));
        assert_eq!(config.web_server.port, 7500);
        assert!(config.transport.tls.as_ref().expect("tls config").force);
        assert_eq!(config.allow_ports.len(), 1);
        assert_eq!(config.allow_ports[0].start, Some(10000));
    }

    /// 含原版暂不支持字段（log.*、loginFailExit 等）的配置必须仍能加载，
    /// 不支持项以 WARN 提示而非硬性拒绝。
    #[test]
    fn test_upstream_config_with_unsupported_fields_still_loads() {
        let path = write_temp_config(
            "frpc_partial",
            r#"
serverAddr = "203.0.113.10"
serverPort = 7000
loginFailExit = false
metasVar = "unused"

log.to = "./frpc.log"
log.level = "info"
log.maxDays = 3

[[proxies]]
name = "ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6022
"#,
        );
        let config = ConfigLoader::load_client_config(&path)
            .expect("config with unsupported upstream fields must still load");
        std::fs::remove_file(&path).ok();

        assert_eq!(config.server_addr, "203.0.113.10");
        assert_eq!(config.proxies.len(), 1);
    }
}

#[cfg(test)]
pub(crate) fn compat_test_counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}
