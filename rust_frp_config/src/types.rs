//! 配置数据结构定义（Server/Client/Proxy/Transport 等）。
//!
//! 从 lib.rs 拆出，保持 `rust_frp_config::` 下的公开路径不变。

use super::*;

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
    ///
    /// 配置后服务端在该端口上起 KCP endpoint；客户端 `transport.protocol = "kcp"` 即可接入。
    /// 注意：KCP 为明文 UDP，与 `tls_only` 互斥（配置校验会拒绝）。
    #[serde(alias = "kcpBindPort")]
    pub kcp_bind_port: Option<u16>,

    /// QUIC 协议绑定端口（可选，UDP）
    ///
    /// 配置后服务端在该端口上起 QUIC endpoint；客户端 `transport.protocol = "quic"`
    /// 即可通过 QUIC 建立控制连接与工作连接（工作连接为同一 QUIC 连接上的新双向流）。
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

    /// 允许客户端注册的自定义域名白名单（可选）
    ///
    /// # 安全说明
    ///
    /// 客户端提交的 `custom_domains` 决定 vhost 路由表的 Host 匹配项。此前服务端
    /// 既不校验域名语法也不校验归属 ⇒ **任意客户端可注册任意域名**（含他人域名）
    /// 抢占 Host 匹配。本字段用于收口：
    ///
    /// - **为空**（默认）：只做域名语法校验（畸形域名一律拒绝注册），不限制归属；
    /// - **非空**：客户端注册的每个域名都必须落在白名单内，否则该代理注册失败。
    ///
    /// # 匹配规则
    ///
    /// - 精确匹配：`example.com` 只放行 `example.com`；
    /// - 白名单通配：`*.example.com` 放行其**严格子域**（含客户端注册的通配
    ///   `*.example.com` 自身），但**不放行 apex `example.com`**——需要 apex
    ///   时另写一条精确条目。
    ///
    /// # 配置示例
    ///
    /// ```toml
    /// custom_domains_allowlist = ["app.example.com", "*.corp.example.com"]
    /// ```
    #[serde(alias = "customDomainsAllowlist")]
    pub custom_domains_allowlist: Vec<String>,

    /// 自定义 404 页面路径（可选）
    #[serde(alias = "custom404Page")]
    pub custom_404_page: Option<String>,

    /// 日志配置（对齐原版 frp 的 `[log]` 段）
    pub log: LogConfig,

    /// 旧版 INI 风格日志文件路径（`log_file`，等价于 `log.to`）
    ///
    /// 原版 frp 在 INI 时代使用顶层 `log_file`；新式 TOML/YAML 使用
    /// `log.to`。两者都接受，**`log.to` 优先**。详见 [`LogConfig`]。
    #[serde(alias = "logFile")]
    pub log_file: Option<String>,

    /// 旧版 INI 风格日志级别（`log_level`，等价于 `log.level`）
    #[serde(alias = "logLevel")]
    pub log_level: Option<String>,

    /// 旧版 INI 风格日志保留天数（`log_max_days`，等价于 `log.maxDays`）
    #[serde(alias = "logMaxDays")]
    pub log_max_days: Option<u32>,

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
            custom_domains_allowlist: Vec::new(),
            custom_404_page: None,
            log: LogConfig::default(),
            log_file: None,
            log_level: None,
            log_max_days: None,
            includes: None,
            proxies: Vec::new(),
            http_plugins: Vec::new(),
        }
    }
}

/// 校验一个自定义域名（HTTP/HTTPS/tcpmux 代理的 `custom_domains` 项）
///
/// # 规则
///
/// - 可选的前导通配符 `*.`：只允许出现在最前面、只允许一层；
/// - 其余部分按 DNS 主机名：以 `.` 分标签，每标签 1–63 字符、仅含
///   `A-Za-z0-9-`、不得以 `-` 开头或结尾；
/// - 整串长度 ≤ 253，不允许空标签（首尾 `.` 或连续 `.`）。
///
/// # 为什么需要
///
/// 客户端提交的 `custom_domains` 会被并进 vhost 路由表决定 Host 匹配。
/// 语法校验挡住畸形输入，归属校验见 [`ServerConfig::custom_domains_allowlist`]。
///
/// # 示例
///
/// ```
/// use rust_frp_config::validate_custom_domain;
/// assert!(validate_custom_domain("app.example.com").is_ok());
/// assert!(validate_custom_domain("*.example.com").is_ok());
/// assert!(validate_custom_domain("bad_underscore.example.com").is_err());
/// assert!(validate_custom_domain("evil..example.com").is_err());
/// ```
pub fn validate_custom_domain(domain: &str) -> Result<(), String> {
    let d = domain.trim();
    if d.is_empty() {
        return Err("domain is empty".to_string());
    }
    if d.len() > 253 {
        return Err(format!("domain is too long ({} bytes > 253)", d.len()));
    }
    // 前导通配符：只允许一层且只在最前面
    let rest = d.strip_prefix("*.").unwrap_or(d);
    if rest.contains('*') {
        return Err("wildcard '*' is only allowed as a single leading '*.' label".to_string());
    }
    if rest.is_empty() {
        return Err("wildcard must be followed by a domain".to_string());
    }
    for label in rest.split('.') {
        if label.is_empty() {
            return Err("empty label (leading/trailing/doubled '.')".to_string());
        }
        if label.len() > 63 {
            return Err(format!("label {label:?} is longer than 63 characters"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("label {label:?} must not start or end with '-'"));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(format!(
                "label {label:?} contains characters outside [A-Za-z0-9-]"
            ));
        }
    }
    Ok(())
}

/// 客户端配置 - 定义 FRP 客户端的所有配置选项
///
/// # 配置示例
///
/// ```toml
/// server_addr = "<SERVER_IP>"
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
    ///
    /// # 说明
    ///
    /// - 未设置时客户端进程会**随机生成**一个，并在整个进程生命周期（含配置热重载）
    ///   内保持不变；**不会**退化为主机名
    /// - 同一 `client_id` 的新登录会被服务端判定为"同一客户端重连"，踢掉旧会话并等其
    ///   释放端口 —— 因此多台主机部署时应显式配置**互不相同**的 `client_id`
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

    /// 日志配置（对齐原版 frp 的 `[log]` 段）
    pub log: LogConfig,

    /// 旧版 INI 风格日志文件路径（`log_file`，等价于 `log.to`）
    #[serde(alias = "logFile")]
    pub log_file: Option<String>,

    /// 旧版 INI 风格日志级别（`log_level`，等价于 `log.level`）
    #[serde(alias = "logLevel")]
    pub log_level: Option<String>,

    /// 旧版 INI 风格日志保留天数（`log_max_days`，等价于 `log.maxDays`）
    #[serde(alias = "logMaxDays")]
    pub log_max_days: Option<u32>,

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
            log: LogConfig::default(),
            log_file: None,
            log_level: None,
            log_max_days: None,
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

/// 日志配置（对齐原版 frp）
///
/// # 两种写法都支持
///
/// 原版 frp 在 INI 时代用顶层 `log_file` / `log_level` / `log_max_days`；
/// 新式 TOML/YAML 用 `[log]` 段（`to` / `level` / `maxDays`）。本实现**同时接受**，
/// 冲突时 **`[log]` 段优先**。
///
/// ```toml
/// # 推荐（原版新式写法）
/// [log]
/// to = "/var/log/frps.log"
/// level = "info"
/// maxDays = 3
///
/// # 同时兼容旧写法（顶层）
/// log_file = "/var/log/frps.log"
/// log_level = "info"
/// log_max_days = 3
/// ```
///
/// # 语义
///
/// - `to` 为空 / 未配置 → 仅输出到 stderr（保持原有行为，systemd 走 journald）；
/// - `to` 配置后 → **同时**输出到 stderr 与文件（tee），便于 journald 与文件双通道排查；
/// - `level` 未配置 → 沿用 `RUST_LOG` 环境变量，再没有则用内置默认级别；
/// - `maxDays` 默认 3，按天轮转，`0` 表示不自动清理；
/// - 文件追加写入，父目录不存在时自动创建。
#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq)]
#[serde(default)]
pub struct LogConfig {
    /// 日志文件路径（空 = 仅 stderr）
    #[serde(alias = "file", alias = "logFile")]
    pub to: Option<String>,

    /// 日志级别（如 `info` / `debug`；也接受 `RUST_LOG` 风格的过滤表达式）
    #[serde(alias = "logLevel")]
    pub level: Option<String>,

    /// 日志文件保留天数（默认 3，0 = 不自动清理）
    #[serde(alias = "maxDays")]
    pub max_days: Option<u32>,
}

/// 合并 `[log]` 段与旧版顶层字段后的最终日志配置
///
/// 由 [`ServerConfig::resolved_log`] / [`ClientConfig::resolved_log`] 产出，
/// 供 `rust_frp_util::logging::init` 使用（该函数只接收原始类型，避免工具 crate
/// 反向依赖配置 crate）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLog {
    /// 日志文件路径（None = 仅 stderr）
    pub to: Option<String>,
    /// 日志级别过滤表达式（None = 用 `RUST_LOG` 或内置默认）
    pub level: Option<String>,
    /// 日志文件保留天数（默认 3，0 = 不自动清理）
    pub max_days: u32,
}

/// 日志文件保留天数默认值（对齐原版 frp）
pub const DEFAULT_LOG_MAX_DAYS: u32 = 3;

impl Default for ResolvedLog {
    /// 默认：仅 stderr、级别交由 `RUST_LOG`、保留 3 天
    fn default() -> Self {
        Self {
            to: None,
            level: None,
            max_days: DEFAULT_LOG_MAX_DAYS,
        }
    }
}

impl LogConfig {
    /// 与旧版顶层字段合并；`[log]` 段优先，顶层仅在段内未配置时兜底
    ///
    /// 空字符串（含纯空白）视为「未配置」，避免 `log_file = ""` 被当成合法路径。
    fn merge(
        &self,
        legacy_to: Option<&String>,
        legacy_level: Option<&String>,
        legacy_max_days: Option<u32>,
    ) -> ResolvedLog {
        let pick = |sect: Option<&String>, legacy: Option<&String>| -> Option<String> {
            sect.or(legacy)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };

        ResolvedLog {
            to: pick(self.to.as_ref(), legacy_to),
            level: pick(self.level.as_ref(), legacy_level),
            max_days: self
                .max_days
                .or(legacy_max_days)
                .unwrap_or(DEFAULT_LOG_MAX_DAYS),
        }
    }
}

impl ServerConfig {
    /// 合并 `[log]` 段与旧版顶层 `log_file` / `log_level` / `log_max_days`
    pub fn resolved_log(&self) -> ResolvedLog {
        self.log.merge(
            self.log_file.as_ref(),
            self.log_level.as_ref(),
            self.log_max_days,
        )
    }
}

impl ClientConfig {
    /// 合并 `[log]` 段与旧版顶层 `log_file` / `log_level` / `log_max_days`
    pub fn resolved_log(&self) -> ResolvedLog {
        self.log.merge(
            self.log_file.as_ref(),
            self.log_level.as_ref(),
            self.log_max_days,
        )
    }
}

/// 服务端对 `client_id` 退化形态（为空 / 等于主机名）的处置策略
///
/// 见 [`AuthConfig::client_id_policy`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientIdPolicy {
    /// 仅 WARN 放行（默认）：兼容旧客户端，先观察一个版本
    #[default]
    Warn,
    /// 硬拒登录（fail-closed）：从根上消除同名主机的"自伤互踢"
    Reject,
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

    /// 动态令牌来源（`method = "token"` 时可用；与静态 `token` 互斥）
    ///
    /// 对齐原版 frp 的 `auth.tokenSource`：避免把明文 token 写进配置文件，
    /// 改由文件或外部命令在客户端启动（及配置重载）时提供。
    #[serde(alias = "tokenSource")]
    pub token_source: Option<TokenSource>,

    /// 额外签名范围（对齐原版 frp 的 `auth.additionalScopes`）
    ///
    /// 可选值：`"heartBeats"`（心跳 Ping 附带 HMAC 签名并由服务端强校验）、
    /// `"newWorkConns"`（工作连接签名；rust 始终强制签名，此值仅为配置兼容）。
    /// `heartBeats` 需要 `auth.method = "token"`（签名密钥来自 token，fail-closed）。
    #[serde(alias = "additionalScopes")]
    pub additional_scopes: Option<Vec<String>>,

    /// 服务端对 `client_id` 退化形态的处置策略（`warn` / `reject`）
    ///
    /// 客户端未配 `client_id` 时本应随机生成；一旦退化为**主机名**或**空**，
    /// 两台同名主机就会被 `kick_same_client` 判为同一客户端而无限互踢
    /// （2026-10-05 线上事故，全线端口掉线约 3 分钟）。
    ///
    /// - `warn`（默认）：只打 WARN 放行 —— 兼容旧客户端，先观察一个版本；
    /// - `reject`：硬拒登录，从根上消除"自伤互踢"。
    #[serde(alias = "clientIdPolicy")]
    pub client_id_policy: ClientIdPolicy,

    /// 控制口登录失败节流：同一 `client_id` 连续失败多少次后锁定。`0` = 关闭节流。
    ///
    /// 以 `client_id` 为主维度（线上两台均为动态 IP + NAT，纯按 IP 会误伤）。
    /// 登录成功即清零。
    #[serde(alias = "loginMaxFailures")]
    pub login_max_failures: u32,

    /// 登录失败锁定时长（秒）。仅在 `login_max_failures > 0` 时生效。
    #[serde(alias = "loginLockoutSecs")]
    pub login_lockout_secs: u64,

    /// 会话接管（kick）是否要求新旧连接**证书指纹一致**。
    ///
    /// 仅在与 mTLS 同用时才有意义：`true` 时，若新旧两端**都有**证书指纹，
    /// 则只有指纹相同才允许接管（攻击者拿到 token + 猜到 client_id 也踢不掉合法客户端）；
    /// 任一端无指纹（灰度期客户端未出示证书）则退回旧的按 `client_id` 判定，
    /// 以保证断线重连仍能正常释放端口。
    #[serde(alias = "kickRequireSameCert")]
    pub kick_require_same_cert: bool,

    /// OIDC 配置（当 method = "oidc" 时使用）
    pub oidc: Option<OidcConfig>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            method: "token".to_string(),
            token: None,
            token_source: None,
            additional_scopes: None,
            client_id_policy: ClientIdPolicy::Warn,
            // 默认开启节流但阈值宽松（正常客户端不会连续 5 次登录失败）；置 0 可完全关闭。
            login_max_failures: 5,
            login_lockout_secs: 600,
            kick_require_same_cert: false,
            oidc: None,
        }
    }
}

/// 动态令牌来源（对齐原版 frp 的 `auth.tokenSource`）
///
/// - `type = "file"`：从 `file_path` 读取令牌（去除首尾空白）
/// - `type = "exec"`：执行 `exec`（`exec[0]` 为程序，其余为参数），取 stdout 为令牌
///
/// 与 `auth.token` 互斥。解析发生在客户端启动与配置重载时，解析结果只写入
/// 内存中的 `auth.token`（不落盘），供登录、工作连接签名与应用层加密统一读取。
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(default)]
pub struct TokenSource {
    /// 来源类型：`"file"` 或 `"exec"`
    pub r#type: String,

    /// 令牌文件路径（`type = "file"`）
    #[serde(alias = "filePath")]
    pub file_path: Option<String>,

    /// 命令及参数（`type = "exec"`，`exec[0]` 为可执行文件）
    pub exec: Option<Vec<String>>,
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
///
/// # QUIC (quic)
///
/// `protocol = "quic"` 时的传输参数，对齐原版 frp 的 `transport.quic.*`
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(default)]
pub struct QuicConfig {
    /// QUIC 空闲超时（秒）；0 表示禁用空闲超时
    ///
    /// # 默认值
    ///
    /// **30**（对齐原版 frp）
    #[serde(alias = "maxIdleTimeout")]
    pub max_idle_timeout: Option<u64>,

    /// QUIC 允许对端并发打开的双向流上限
    ///
    /// # 默认值
    ///
    /// **100000**（对齐原版 frp）
    #[serde(alias = "maxIncomingStreams")]
    pub max_incoming_streams: Option<u32>,

    /// QUIC 保活间隔（秒）；0 或未配置表示不主动保活
    #[serde(alias = "keepalivePeriod")]
    pub keepalive_period: Option<u64>,
}

/// 服务端连接池上限的默认值：**0 = 不限**（对齐原版 frp `transport.maxPoolCount`）
///
/// 默认不设上限时，客户端配置多少就允许多少；需要约束单客户端资源占用时
/// 再显式配置 `max_pool_count`。
pub const DEFAULT_MAX_POOL_COUNT: u32 = 0;

/// 工作连接 TCP keepalive 空闲时间的默认值（秒）
///
/// 取 30s 是为了在任何常见 NAT 空闲超时（通常 ≥ 300s）之前刷新表项。
pub const DEFAULT_TCP_KEEPALIVE_SECS: u64 = 30;

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct TransportConfig {
    /// 传输协议: "tcp", "kcp", "quic", "websocket", "wss"
    ///
    /// # 说明
    ///
    /// - `websocket`：明文 WebSocket（可在其上叠加 TLS，由 `transport.tls.enable` 控制）
    /// - `wss`：**强制** TLS + WebSocket（等价于原版 frp 的 `protocol = "wss"`），
    ///   要求 `transport.tls` 中配置 `trusted_ca_file` 或 `skip_verify = true`
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

    /// 客户端预建立的工作连接数量（对齐原版 frp `transport.poolCount`）
    ///
    /// # 默认值
    ///
    /// **0**（与原版 frp 一致）：只在访问者连接到来时才请求工作连接。
    ///
    /// # 什么时候该调大
    ///
    /// 大量**短连接**场景下，预建可以省掉「请求工作连接 → 建连 → 握手」这一
    /// 个往返（实测约 50~100 ms）。代价是常驻 `pool_count × 代理数` 条空闲
    /// TLS 连接，且这些连接需要 keepalive 续命（见 `tcp_keepalive_secs`），
    /// 否则会被云上 NAT 回收后立刻重建，反而制造握手风暴。
    ///
    /// # 何时不要开
    ///
    /// 启用 `tcp_mux`（默认开启）时，原版 frp 文档明确说连接池收益有限——
    /// 多路复用本身已经把建连成本摊薄了。
    #[serde(alias = "poolCount")]
    pub pool_count: u32,

    /// 服务端允许的连接池上限（对齐原版 frp `transport.maxPoolCount`）
    ///
    /// 客户端请求的 `pool_count` 超过此值时按此值收敛（不报错）。
    /// 与 `pool_count` 分离的原因：原版 frp 里这两个参数本来就是「客户端想开多少」
    /// 与「服务端允许开多少」两件事，混用一个字段会导致客户端把默认值改小时
    /// 服务端上限一起塌掉。
    ///
    /// # 默认值
    ///
    /// 未配置时为 **0 = 不限**（与原版 frp 一致，由客户端 `pool_count` 自行决定）。
    /// 需要防止单客户端开过大池时再显式配置本项。
    #[serde(alias = "maxPoolCount")]
    pub max_pool_count: Option<u32>,

    /// 工作连接 TCP keepalive 空闲时间（秒），0 表示禁用
    ///
    /// # 为什么需要
    ///
    /// 专用工作端口（双端口模式）上的连接在没有业务流量时是**完全空闲**的，
    /// 云上 NAT / 安全组通常会在 5~10 分钟内回收空闲 TCP。没有 keepalive 时，
    /// 对端要到下次写入才发现连接已死；连接池还会以为这些连接可用。
    ///
    /// 开启后内核会按该间隔发探测包，NAT 表项得以续期，死连接也能被及时清掉。
    ///
    /// # 取值建议
    ///
    /// 小于链路上 NAT 的空闲超时（常见 300s）。默认 30s 足够保守。
    ///
    /// **0** = 关闭（不推荐，除非链路没有中间 NAT）。
    #[serde(alias = "tcpKeepaliveSecs")]
    pub tcp_keepalive_secs: u64,

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

    /// QUIC 传输参数（`protocol = "quic"` 时生效，兼容原版 `transport.quic`）
    #[serde(default)]
    pub quic: Option<QuicConfig>,

    /// 线协议版本（**客户端生效**，对齐原版 frp `transport.wireProtocol`）
    ///
    /// - `"v1"`（默认）：`[4B 长度][JSON]` 明文控制通道；
    /// - `"v2"`：魔数 `FRP\x00\x02\r\n` + ClientHello/ServerHello 能力协商 +
    ///   方向性 AEAD（AES-256-GCM，密钥由 HKDF 从 token 派生）加密控制通道。
    ///
    /// # 说明
    ///
    /// - 服务端自动嗅探魔数，**无需**配置此项（配置后会被忽略）；
    /// - `v2` 依赖 token 派生的基础密钥，因此要求 `auth.method = "token"`；
    /// - 当前作用于控制连接，工作连接仍沿用 v1 帧格式。
    ///
    /// 注意：此处**不加**字段级 `#[serde(default)]`——否则会以 `String::default()`
    /// （空串）覆盖容器级 `#[serde(default)]`，使缺省值为空串而非 `"v1"`。
    #[serde(alias = "wireProtocol")]
    pub wire_protocol: String,

    /// 工作连接承载方式（**客户端生效**，数据/控制分离架构开关）
    ///
    /// - `"auto"`（默认）：优先直拨服务器专用工作端口（`work_conn_port`，
    ///   默认 `server_port + 1000`），把数据面与控制面（心跳/控制消息）彻底分开；
    ///   工作端口不可达时（防火墙只放行了一个端口等）自动回退 tcp_mux 会话流，
    ///   保证连通性优先。
    /// - `"mux"`：工作连接始终走 tcp_mux/QUIC 会话流（受限环境，只开一个端口）。
    /// - `"dedicated"`：强制直拨工作端口，失败直接报错（严格分离，不回退）。
    ///
    /// 注意：与 `wire_protocol` 一致**不加**字段级 `#[serde(default)]`——
    /// 容器级 `#[serde(default)]` 会让缺省值取 `Default::default()`（"auto"），
    /// 字段级 default 反而会以空串覆盖它。
    #[serde(alias = "workConnVia")]
    pub work_conn_via: String,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            protocol: "tcp".to_string(),
            tls: None,
            tcp_mux: true,
            tls_only: false,
            // 与原版 frp 对齐：默认不预建工作连接
            pool_count: 0,
            max_pool_count: None,
            tcp_keepalive_secs: DEFAULT_TCP_KEEPALIVE_SECS,
            bandwidth_limit: None,
            use_encryption: false,
            use_compression: false,
            quic: None,
            wire_protocol: "v1".to_string(),
            work_conn_via: "auto".to_string(),
        }
    }
}

impl TransportConfig {
    /// 服务端实际生效的连接池上限；**0 表示不限**
    ///
    /// 客户端 `pool_count` 超过该值时按该值收敛；`pool_count = 0`（默认）
    /// 时客户端根本不请求预建连接，此值不产生任何常驻连接。
    pub fn effective_max_pool_count(&self) -> u32 {
        self.max_pool_count.unwrap_or(DEFAULT_MAX_POOL_COUNT)
    }

    /// 工作连接 keepalive 空闲时间；`None` 表示禁用
    pub fn tcp_keepalive_idle(&self) -> Option<std::time::Duration> {
        match self.tcp_keepalive_secs {
            0 => None,
            secs => Some(std::time::Duration::from_secs(secs)),
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

    /// TLS 证书文件路径
    ///
    /// - **服务器**：服务端叶证书
    /// - **客户端**：客户端证书（mTLS 时出示给服务端校验；须与 `key_file` 成对）
    #[serde(alias = "certFile")]
    pub cert_file: Option<String>,

    /// TLS 私钥文件路径
    ///
    /// - **服务器**：服务端证书私钥
    /// - **客户端**：客户端证书私钥（须与 `cert_file` 成对）
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

    /// 用于校验**客户端证书**的 CA 文件（服务器用）—— 配置后即启用 mTLS
    ///
    /// 服务端在握手阶段用该 CA 校验客户端证书链。两个方向互不相同：
    /// 本项管"服务端验客户端"，`trusted_ca_file` 管"客户端验服务端"。
    ///
    /// ⚠️ **本项不可跳过**：一旦配置，证书链校验即强制生效，不存在"只看有没有证书、
    /// 不验链"的开关 —— 那样的 mTLS 比 token 认证更弱。
    ///
    /// 灰度语义由 `require_client_cert` 决定：`false`（默认）时"出示则校验、未出示放行"，
    /// 便于先铺客户端证书；`true` 时未出示者握手即失败。
    #[serde(alias = "clientCaFile")]
    pub client_ca_file: Option<String>,

    /// 是否强制要求客户端出示证书（服务器用）
    ///
    /// 仅在配置了 `client_ca_file` 时有意义。`false` 仅表示"未出示也放行"这一**过渡**
    /// 语义（灰度铺开用），**不是**"跳过校验"；一旦客户端出示证书，仍严格校验链。
    ///
    /// # 默认值
    ///
    /// **false**
    #[serde(alias = "requireClientCert")]
    pub require_client_cert: bool,

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
            client_ca_file: None,
            require_client_cert: false,
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

    /// PROXY protocol 版本（可选，`"v1"` / `"v2"`，默认 `"v1"`）
    ///
    /// 与 `proxy_protocol` 配合使用；单独设置本字段（不设 `proxy_protocol`）
    /// 也视为启用，与原版 `transport.proxyProtocolVersion` 语义一致。
    #[serde(alias = "proxyProtocolVersion")]
    pub proxy_protocol_version: Option<String>,

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
    /// - `http2http`: 明文 HTTP 接入 → 明文 HTTP 本地服务（可改写 Host / 注入请求头）
    /// - `http2https`: 明文 HTTP 接入 → TLS 本地服务（可改写 Host / 注入请求头）
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

    /// SOCKS5 用户名（socks5 插件用，RFC 1929 认证）
    pub username: Option<String>,

    /// SOCKS5 密码（socks5 插件用，RFC 1929 认证）
    pub password: Option<String>,

    /// 本地地址（http_proxy/socks5 及 TLS 系插件 https2http/tls2raw/https2https 用）
    #[serde(alias = "localAddr")]
    pub local_addr: Option<String>,

    /// 证书文件路径（HTTPS 相关插件用）
    #[serde(alias = "crtPath")]
    pub crt_path: Option<String>,

    /// 私钥文件路径（HTTPS 相关插件用）
    #[serde(alias = "keyPath")]
    pub key_path: Option<String>,

    /// 改写转发到本地服务的 `Host` 请求头（http2http/http2https/https2http 等插件用）
    ///
    /// 为空时保留访客原始 Host（即 `custom_domains` 中的域名）。
    #[serde(alias = "hostHeaderRewrite")]
    pub host_header_rewrite: Option<String>,

    /// 注入/覆盖转发到本地服务的请求头（对齐原版 `HeaderOperations`）
    #[serde(alias = "requestHeaders")]
    pub request_headers: Option<HeaderOperations>,
}

/// 请求头操作（对齐原版 frp v1 `HeaderOperations`）
///
/// TOML 写法：
///
/// ```toml
/// [proxies.plugin]
/// type = "http2https"
/// localAddr = "127.0.0.1:443"
/// requestHeaders.set.x-from-where = "frp"
/// ```
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(default)]
pub struct HeaderOperations {
    /// 需要设置/覆盖的请求头（键大小写不敏感匹配后覆盖）
    pub set: std::collections::HashMap<String, String>,
}
