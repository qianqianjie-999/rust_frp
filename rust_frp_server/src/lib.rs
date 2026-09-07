//! FRP 服务器模块
//!
//! 该模块实现了 FRP 服务器（frps）的核心功能。
//!
//! ## 服务器架构
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         Server                                   │
//! │  (主服务器结构，管理所有子组件)                                   │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!         ┌────────────────────┼────────────────────┐
//!         ▼                    ▼                    ▼
//! ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
//! │ControlManager │   │ServerProxyMgr │   │ServerVisitorMgr│
//! │ (控制器管理)   │   │ (代理管理)     │   │ (访问者管理)   │
//! └───────────────┘   └───────────────┘   └───────────────┘
//!         │                    │                    │
//!         ▼                    ▼                    ▼
//! ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
//! │   Control     │   │ HttpVhostRouter│  │ WorkConnManager│
//! │ (控制连接)     │   │ (HTTP路由)     │   │ (工作连接管理) │
//! └───────────────┘   └───────────────┘   └───────────────┘
//! ```
//!
//! ## 核心流程
//!
//! ### 1. 客户端连接流程
//! ```text
//! 客户端                          服务器
//!   │                               │
//!   │------ TCP/TLS 连接 --------->│
//!   │                               │
//!   │------ LoginMsg ------------->│
//!   │                               │ 验证 token
//!   │<----- LoginRespMsg ----------│
//!   │                               │
//!   │------ RegisterProxyMsg ----->│
//!   │                               │ 注册代理
//!   │<----- RegisterProxyResp ----│
//!   │                               │
//! ```
//!
//! ### 2. TCP 代理请求流程
//! ```text
//! 访问者        服务器                             客户端                 本地
//!   │              │                                 │                   │
//!   │--- TCP 请求 ->│                                 │                   │
//!   │              │ get_work_conn():                 │                   │
//!   │              │   try_recv from pool             │                   │
//!   │              │   pool empty → ReqWorkConnMsg -->│                   │
//!   │              │                                 │ 新建工作连接 ─────│
//!   │              │<------------- NewWorkConn ------│                   │
//!   │              │   pool.send(conn)                │                   │
//!   │              │   StartWorkConn(visitor_addr) -->│                   │
//!   │              │                                 │ connect local ───>│
//!   │              │                                 │ 可选: PROXY header>│
//!   │<--- 桥接 ---- │<---- bridge_streams --------->│<---- bridge ----->│
//! ```
//!
//! ### 3. HTTP 代理请求流程
//! ```text
//! 访问者        服务器（HTTP路由）              客户端
//!   │              │                            │
//!   │--- HTTP 请求 ->│                            │
//!   │              │ 解析 Host 头                │
//!   │              │ 查找域名对应的代理           │
//!   │              │ ReqWorkConnMsg ------------>│
//!   │              │                            │
//!   │              │              新建工作连接 ---│
//!   │              │<-------- NewWorkConn ------│
//!   │              │                            │
//!   │<--- 响应 ---- │-------------------------->│
//!   │              │                            │
//! ```
//!
//! ## 安全特性
//!
//! 1. **端口白名单 (allow_ports)**
//!    - 默认拒绝所有端口
//!    - 只有在白名单中的端口才能使用
//!    - 配置示例：`allow_ports = [{ start = 10000, end = 20000 }]`
//!
//! 2. **Token 认证**
//!    - 客户端登录时验证 token
//!    - 使用常量时间比较防止时序攻击
//!
//! 3. **HMAC 签名**
//!    - 工作连接使用 HMAC-SHA256 签名
//!    - 验证 run_id 和 timestamp
//!
//! 4. **代理所有权**
//!    - 每个代理绑定到创建它的客户端
//!    - 防止未授权访问
//!
//! ## 配置示例
//!
//! ```toml
//! bind_addr = "0.0.0.0"
//! bind_port = 9300
//!
//! [web_server]
//! addr = "0.0.0.0"
//! port = 7500
//! user = "admin"
//! password = "admin"
//!
//! [auth]
//! method = "token"
//! token = "your_secure_token"
//!
//! allow_ports = [
//!     { single = 9302 },
//!     { start = 10000, end = 20000 },
//! ]
//! ```

use axum::extract::State;
use axum::response::IntoResponse;
use rust_frp_auth::AuthManager;
use rust_frp_config::ServerConfig;
use rust_frp_core::{
    ControlConn, Message, ProxyManager, ReqWorkConnMsg, StcpVisitorRespMsg, VisitorManager,
    XtcpHolePunchMsg, XtcpNatInfoMsg,
};
use rust_frp_net::{
    AnyConn, ConnManager, KcpConn, KcpListener, MuxSession, TcpListener, TlsConfig, TCP_MUX_MAGIC,
    UdpListener, WebSocketConn,
};
use rust_frp_util::get_timestamp;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::accept_async;

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("proxy not found: {0}")]
    ProxyNotFound(String),
    #[error("port not allowed: {0}")]
    PortNotAllowed(u16),
    #[error("proxy already exists: {0}")]
    ProxyAlreadyExists(String),
    #[error("work conn request timeout")]
    WorkConnTimeout,
    #[error("run ID mismatch")]
    RunIdMismatch,
    #[error("{0}")]
    Other(String),
}

/// 工作连接管理器
pub struct WorkConnManager {
    /// 等待工作连接的通道 (proxy_name, sender)
    pending_conns: RwLock<std::collections::HashMap<String, mpsc::Sender<tokio::net::TcpStream>>>,
}

impl Default for WorkConnManager {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkConnManager {
    pub fn new() -> Self {
        Self {
            pending_conns: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// 注册一个等待工作连接的请求
    pub async fn register_pending(
        &self,
        proxy_name: String,
    ) -> mpsc::Receiver<tokio::net::TcpStream> {
        let (tx, rx) = mpsc::channel::<tokio::net::TcpStream>(1);
        let mut pending = self.pending_conns.write().await;
        pending.insert(proxy_name, tx);
        rx
    }

    /// 完成一个工作连接
    pub async fn complete_work_conn(
        &self,
        proxy_name: &str,
        work_conn: tokio::net::TcpStream,
    ) -> Result<(), String> {
        let pending = self.pending_conns.read().await;
        if let Some(sender) = pending.get(proxy_name) {
            sender
                .send(work_conn)
                .await
                .map_err(|e| format!("Failed to send work conn: {}", e))?;
            Ok(())
        } else {
            Err(format!(
                "No pending work conn request for proxy: {}",
                proxy_name
            ))
        }
    }
}

/// 服务器工作连接管理器（池模式）
/// 参考 frp 原版设计：预建工作连接池，访客到达时从池中取用。
/// 无 per-request 状态，自然杜绝僵尸条目和内存泄漏。
pub struct ServerWorkConnManager {
    /// 工作连接池 (proxy_name -> pool)
    pools: RwLock<std::collections::HashMap<String, Arc<WorkConnPool>>>,
    /// 每个代理的池大小
    pool_size: usize,
}

/// 单个代理的工作连接池
struct WorkConnPool {
    tx: mpsc::Sender<AnyConn>,
    rx: tokio::sync::Mutex<mpsc::Receiver<AnyConn>>,
}

impl Default for ServerWorkConnManager {
    fn default() -> Self {
        Self::new(10)
    }
}

impl ServerWorkConnManager {
    pub fn new(pool_size: usize) -> Self {
        Self {
            pools: RwLock::new(std::collections::HashMap::new()),
            pool_size,
        }
    }

    /// 为代理初始化工作连接池
    pub async fn init_pool(&self, proxy_name: &str) {
        let (tx, rx) = mpsc::channel::<AnyConn>(self.pool_size);
        let pool = Arc::new(WorkConnPool {
            tx,
            rx: tokio::sync::Mutex::new(rx),
        });
        let mut pools = self.pools.write().await;
        pools.insert(proxy_name.to_string(), pool);
        log::info!(
            "Initialized work conn pool for proxy: {}, capacity: {}",
            proxy_name,
            self.pool_size
        );
    }

    /// 注册工作连接到池中（由 process_work_conn 调用）
    /// 如果池已满，连接将被丢弃并关闭（背压保护）
    pub async fn register_work_conn(&self, proxy_name: &str, mut conn: AnyConn) {
        global_metrics().incr_work_conn_total();
        let pools = self.pools.read().await;
        if let Some(pool) = pools.get(proxy_name) {
            match pool.tx.try_send(conn) {
                Ok(_) => log::debug!("Work conn registered in pool for {}", proxy_name),
                Err(mpsc::error::TrySendError::Full(mut conn)) => {
                    log::warn!(
                        "Work conn pool full for {}, discarding and closing",
                        proxy_name
                    );
                    let _ = conn.shutdown().await;
                }
                Err(mpsc::error::TrySendError::Closed(mut conn)) => {
                    log::debug!(
                        "Work conn pool closed for {}, closing connection",
                        proxy_name
                    );
                    let _ = conn.shutdown().await;
                }
            }
        } else {
            log::warn!(
                "No pool initialized for proxy: {}, discarding and closing work conn",
                proxy_name
            );
            let _ = conn.shutdown().await;
        }
    }

    /// 获取工作连接（供 TCP/HTTP/HTTPS/WebSocket 处理器调用）
    /// 与 frp 原版一致：从池中取 → 发 StartWorkConn，失败则重试 pool_size+1 次，
    /// 成功后立即补充一个请求保持池始终有可用连接。
    pub async fn get_work_conn(
        &self,
        proxy_name: &str,
        msg_tx: &tokio::sync::mpsc::Sender<Message>,
        timeout: Duration,
        visitor_addr: std::net::SocketAddr,
    ) -> Result<AnyConn, String> {
        // 获取代理的池（克隆 Arc，避免生命周期问题）
        let pool: Arc<WorkConnPool> = {
            let pools = self.pools.read().await;
            pools
                .get(proxy_name)
                .ok_or_else(|| format!("Pool not found for proxy: {}", proxy_name))?
                .clone()
        };

        let max_retries = self.pool_size + 1;
        let mut last_err = String::new();

        for retry in 0..max_retries {
            // 1. 从池中获取连接（池空则请求+等待）
            let mut conn = {
                let mut rx = pool.rx.lock().await;
                match rx.try_recv() {
                    Ok(c) => c,
                    Err(mpsc::error::TryRecvError::Empty) => {
                        drop(rx);
                        log::debug!(
                            "Pool empty for {}, requesting new work conn (retry {}/{})",
                            proxy_name,
                            retry + 1,
                            max_retries
                        );
                        let req = Message::ReqWorkConn(rust_frp_core::ReqWorkConnMsg {
                            proxy_name: proxy_name.to_string(),
                        });
                        msg_tx
                            .send(req)
                            .await
                            .map_err(|e| format!("Failed to send ReqWorkConn: {}", e))?;

                        let mut rx = pool.rx.lock().await;
                        match tokio::time::timeout(timeout, rx.recv()).await {
                            Ok(Some(c)) => c,
                            Ok(None) => return Err("Pool channel closed".to_string()),
                            Err(_) => {
                                return Err(format!(
                                    "Timeout waiting for work conn for {}",
                                    proxy_name
                                ))
                            }
                        }
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        return Err("Pool disconnected".to_string());
                    }
                }
            };

            // 2. 发送 StartWorkConn 唤醒客户端（携带访问者地址，用于 PROXY protocol）
            let resp = Message::StartWorkConn(rust_frp_core::StartWorkConnMsg {
                error: "".to_string(),
                src_addr: visitor_addr.ip().to_string(),
                src_port: visitor_addr.port(),
                dst_addr: "127.0.0.1".to_string(),
                dst_port: 0,
            });
            match rust_frp_core::write_message(&mut conn, &resp).await {
                Ok(_) => {
                    // 成功后立即补充，保持池始终有可用连接（与 frp 原版一致）
                    let req = Message::ReqWorkConn(rust_frp_core::ReqWorkConnMsg {
                        proxy_name: proxy_name.to_string(),
                    });
                    let _ = msg_tx.try_send(req);
                    return Ok(conn);
                }
                Err(e) => {
                    last_err = format!("Failed to send StartWorkConn: {}", e);
                    log::warn!(
                        "{} for proxy {} (retry {}/{})",
                        last_err,
                        proxy_name,
                        retry + 1,
                        max_retries
                    );
                    // 连接已损坏，丢弃，继续重试
                    drop(conn);
                }
            }
        }

        Err(format!(
            "All {} retries exhausted for {}: {}",
            max_retries, proxy_name, last_err
        ))
    }

    /// 移除代理的池（代理停止时调用）
    pub async fn remove_pool(&self, proxy_name: &str) {
        let mut pools = self.pools.write().await;
        pools.remove(proxy_name);
        log::info!("Removed work conn pool for {}", proxy_name);
    }
}

/// HTTP 请求信息
#[derive(Debug, Clone)]
pub struct HttpRequestInfo {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: std::collections::HashMap<String, String>,
    pub host: String,
}

impl HttpRequestInfo {
    /// 从原始 HTTP 请求数据解析
    pub fn parse(data: &[u8]) -> Option<Self> {
        let request_str = String::from_utf8_lossy(data);
        let lines: Vec<&str> = request_str.lines().collect();
        if lines.is_empty() {
            return None;
        }

        // 解析请求行
        let first_line = lines[0];
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 3 {
            return None;
        }

        let method = parts[0].to_string();
        let path = parts[1].to_string();
        let version = parts[2].to_string();

        // 解析请求头
        let mut headers = std::collections::HashMap::new();
        let mut host = String::new();

        for line in &lines[1..] {
            if line.is_empty() {
                break;
            }
            if let Some(idx) = line.find(':') {
                let key = line[..idx].trim().to_lowercase();
                let value = line[idx + 1..].trim().to_string();
                if key == "host" {
                    // 去除端口号
                    host = value.split(':').next().unwrap_or(&value).to_string();
                }
                headers.insert(key, value);
            }
        }

        if host.is_empty() {
            return None;
        }

        Some(Self {
            method,
            path,
            version,
            headers,
            host,
        })
    }

    /// 检查是否是 WebSocket 升级请求
    pub fn is_websocket_upgrade(&self) -> bool {
        // 检查 Connection 头是否包含 "Upgrade"
        if let Some(connection) = self.headers.get("connection") {
            if !connection.to_lowercase().contains("upgrade") {
                return false;
            }
        } else {
            return false;
        }

        // 检查 Upgrade 头是否为 "websocket"
        if let Some(upgrade) = self.headers.get("upgrade") {
            upgrade.to_lowercase() == "websocket"
        } else {
            false
        }
    }

    /// 获取 Sec-WebSocket-Key
    pub fn get_websocket_key(&self) -> Option<&str> {
        self.headers.get("sec-websocket-key").map(|s| s.as_str())
    }

    /// 生成 WebSocket 接受密钥
    pub fn generate_websocket_accept_key(key: &str) -> String {
        use base64::encode;
        use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};

        let magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        let combined = format!("{}{}", key, magic_string);

        let mut context = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
        context.update(combined.as_bytes());
        let digest = context.finish();

        encode(digest.as_ref())
    }
}

/// HTTP 虚拟主机路由器
pub struct HttpVhostRouter {
    // domain -> proxy_name
    domain_map: RwLock<std::collections::HashMap<String, String>>,
    // proxy_name -> proxy config
    proxy_configs: RwLock<std::collections::HashMap<String, rust_frp_config::ProxyConfig>>,
}

impl Default for HttpVhostRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpVhostRouter {
    pub fn new() -> Self {
        Self {
            domain_map: RwLock::new(std::collections::HashMap::new()),
            proxy_configs: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// 注册 HTTP 代理的域名映射
    pub async fn register_proxy(
        &self,
        proxy_name: String,
        domains: Vec<String>,
        config: rust_frp_config::ProxyConfig,
    ) {
        let mut domain_map = self.domain_map.write().await;
        for domain in domains {
            log::info!("Registering domain '{}' for proxy '{}'", domain, proxy_name);
            domain_map.insert(domain, proxy_name.clone());
        }

        let mut proxy_configs = self.proxy_configs.write().await;
        proxy_configs.insert(proxy_name, config);
    }

    /// 注销 HTTP 代理
    pub async fn unregister_proxy(&self, proxy_name: &str) {
        let mut domain_map = self.domain_map.write().await;
        domain_map.retain(|_, v| v != proxy_name);

        let mut proxy_configs = self.proxy_configs.write().await;
        proxy_configs.remove(proxy_name);
    }

    /// 根据 Host 查找代理名称
    pub async fn find_proxy_by_host(&self, host: &str) -> Option<String> {
        let domain_map = self.domain_map.read().await;

        // 首先尝试精确匹配
        if let Some(proxy_name) = domain_map.get(host) {
            return Some(proxy_name.clone());
        }

        // 尝试子域名匹配
        for (domain, proxy_name) in domain_map.iter() {
            if host.ends_with(domain) {
                return Some(proxy_name.clone());
            }
        }

        None
    }

    /// 获取代理配置
    pub async fn get_proxy_config(&self, proxy_name: &str) -> Option<rust_frp_config::ProxyConfig> {
        let proxy_configs = self.proxy_configs.read().await;
        proxy_configs.get(proxy_name).cloned()
    }
}

/// 单个代理的运行时统计（per-proxy 指标）
pub struct ProxyStat {
    pub name: String,
    pub proxy_type: String,
    pub remote_port: Option<u16>,
    pub current_conns: AtomicUsize,
    pub total_conns: AtomicUsize,
}

impl ProxyStat {
    fn new(name: &str, proxy_type: &str, remote_port: Option<u16>) -> Self {
        Self {
            name: name.to_string(),
            proxy_type: proxy_type.to_string(),
            remote_port,
            current_conns: AtomicUsize::new(0),
            total_conns: AtomicUsize::new(0),
        }
    }
}

/// 代理连接统计守卫：创建时 current/total +1，drop 时 current -1，
/// 覆盖任务内所有 return 路径
pub struct ProxyConnGuard {
    stat: std::sync::Arc<ProxyStat>,
}

impl ProxyConnGuard {
    pub fn acquire(stat: std::sync::Arc<ProxyStat>) -> Self {
        stat.total_conns.fetch_add(1, Ordering::SeqCst);
        stat.current_conns.fetch_add(1, Ordering::SeqCst);
        Self { stat }
    }
}

impl Drop for ProxyConnGuard {
    fn drop(&mut self) {
        self.stat.current_conns.fetch_sub(1, Ordering::SeqCst);
    }
}

/// 监控指标
pub struct MonitorMetrics {
    total_connections: AtomicUsize,
    current_connections: AtomicUsize,
    total_proxies: AtomicUsize,
    current_proxies: AtomicUsize,
    bytes_sent: AtomicUsize,
    bytes_received: AtomicUsize,
    start_time: Instant,
    /// 登录失败累计
    login_failures: AtomicUsize,
    /// 登录成功累计
    login_successes: AtomicUsize,
    /// TLS 握手拒绝累计（tls_only / 非法客户端）
    tls_rejects: AtomicUsize,
    /// 工作连接注册累计
    work_conn_total: AtomicUsize,
    /// per-proxy 统计表（proxy_name -> 指标）
    proxy_stats: std::sync::RwLock<std::collections::HashMap<String, std::sync::Arc<ProxyStat>>>,
}

impl Default for MonitorMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitorMetrics {
    pub fn new() -> Self {
        Self {
            total_connections: AtomicUsize::new(0),
            current_connections: AtomicUsize::new(0),
            total_proxies: AtomicUsize::new(0),
            current_proxies: AtomicUsize::new(0),
            bytes_sent: AtomicUsize::new(0),
            bytes_received: AtomicUsize::new(0),
            start_time: Instant::now(),
            login_failures: AtomicUsize::new(0),
            login_successes: AtomicUsize::new(0),
            tls_rejects: AtomicUsize::new(0),
            work_conn_total: AtomicUsize::new(0),
            proxy_stats: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    pub fn increment_connections(&self) {
        self.total_connections.fetch_add(1, Ordering::SeqCst);
        self.current_connections.fetch_add(1, Ordering::SeqCst);
    }

    pub fn decrement_connections(&self) {
        self.current_connections.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn increment_proxies(&self) {
        self.total_proxies.fetch_add(1, Ordering::SeqCst);
        self.current_proxies.fetch_add(1, Ordering::SeqCst);
    }

    pub fn decrement_proxies(&self) {
        self.current_proxies.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn add_bytes_sent(&self, bytes: usize) {
        self.bytes_sent.fetch_add(bytes, Ordering::SeqCst);
    }

    pub fn add_bytes_received(&self, bytes: usize) {
        self.bytes_received.fetch_add(bytes, Ordering::SeqCst);
    }

    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    pub fn get_metrics(&self) -> serde_json::Value {
        serde_json::json! {
            {
                "uptime": self.uptime().as_secs(),
                "total_connections": self.total_connections.load(Ordering::SeqCst),
                "current_connections": self.current_connections.load(Ordering::SeqCst),
                "total_proxies": self.total_proxies.load(Ordering::SeqCst),
                "current_proxies": self.current_proxies.load(Ordering::SeqCst),
                "bytes_sent": self.bytes_sent.load(Ordering::SeqCst),
                "bytes_received": self.bytes_received.load(Ordering::SeqCst),
            }
        }
    }

    pub fn incr_login_failures(&self) {
        self.login_failures.fetch_add(1, Ordering::SeqCst);
    }

    pub fn incr_login_successes(&self) {
        self.login_successes.fetch_add(1, Ordering::SeqCst);
    }

    pub fn incr_tls_rejects(&self) {
        self.tls_rejects.fetch_add(1, Ordering::SeqCst);
    }

    pub fn incr_work_conn_total(&self) {
        self.work_conn_total.fetch_add(1, Ordering::SeqCst);
    }

    /// 代理注册成功时创建 per-proxy 统计
    pub fn register_proxy_stat(
        &self,
        name: &str,
        proxy_type: &str,
        remote_port: Option<u16>,
    ) -> std::sync::Arc<ProxyStat> {
        let stat = std::sync::Arc::new(ProxyStat::new(name, proxy_type, remote_port));
        self.proxy_stats
            .write()
            .unwrap()
            .insert(name.to_string(), stat.clone());
        stat
    }

    /// 代理注销时移除统计
    pub fn remove_proxy_stat(&self, name: &str) {
        self.proxy_stats.write().unwrap().remove(name);
    }

    /// 获取代理统计（用于连接计数守卫）
    pub fn get_proxy_stat(&self, name: &str) -> Option<std::sync::Arc<ProxyStat>> {
        self.proxy_stats.read().unwrap().get(name).cloned()
    }

    /// 输出 Prometheus text exposition format (v0.0.4)。
    /// 手写实现，零第三方依赖；label 值做转义防止注入。
    ///
    /// 说明：bytes_sent/bytes_received 当前未在数据面接线，恒为 0（best-effort）。
    pub fn render_prometheus(&self) -> String {
        fn esc(s: &str) -> String {
            s.replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n")
        }
        fn counter(out: &mut String, name: &str, help: &str, value: usize) {
            out.push_str(&format!(
                "# HELP {} {}\n# TYPE {} counter\n{} {}\n",
                name, help, name, name, value
            ));
        }
        fn gauge(out: &mut String, name: &str, help: &str, value: usize) {
            out.push_str(&format!(
                "# HELP {} {}\n# TYPE {} gauge\n{} {}\n",
                name, help, name, name, value
            ));
        }

        let mut out = String::with_capacity(2048);
        gauge(
            &mut out,
            "frps_uptime_seconds",
            "Server uptime in seconds",
            self.uptime().as_secs() as usize,
        );
        counter(
            &mut out,
            "frps_connections_total",
            "Total visitor connections accepted",
            self.total_connections.load(Ordering::SeqCst),
        );
        gauge(
            &mut out,
            "frps_connections_current",
            "Current visitor connections",
            self.current_connections.load(Ordering::SeqCst),
        );
        counter(
            &mut out,
            "frps_proxies_total",
            "Total proxies registered",
            self.total_proxies.load(Ordering::SeqCst),
        );
        gauge(
            &mut out,
            "frps_proxies_current",
            "Current registered proxies",
            self.current_proxies.load(Ordering::SeqCst),
        );
        counter(
            &mut out,
            "frps_traffic_bytes_sent_total",
            "Bytes sent (not wired in dataplane, always 0)",
            self.bytes_sent.load(Ordering::SeqCst),
        );
        counter(
            &mut out,
            "frps_traffic_bytes_received_total",
            "Bytes received (not wired in dataplane, always 0)",
            self.bytes_received.load(Ordering::SeqCst),
        );
        counter(
            &mut out,
            "frps_login_successes_total",
            "Successful client logins",
            self.login_successes.load(Ordering::SeqCst),
        );
        counter(
            &mut out,
            "frps_login_failures_total",
            "Failed client logins",
            self.login_failures.load(Ordering::SeqCst),
        );
        counter(
            &mut out,
            "frps_tls_rejects_total",
            "TLS handshake rejections",
            self.tls_rejects.load(Ordering::SeqCst),
        );
        counter(
            &mut out,
            "frps_work_conn_total",
            "Work connections registered",
            self.work_conn_total.load(Ordering::SeqCst),
        );

        // per-proxy 指标（label: name/type）
        let stats = self.proxy_stats.read().unwrap();
        for stat in stats.values() {
            let labels = format!(
                "{{name=\"{}\",type=\"{}\"}}",
                esc(&stat.name),
                esc(&stat.proxy_type)
            );
            out.push_str(&format!(
                "# HELP frps_proxy_conns_current Current connections per proxy\n# TYPE frps_proxy_conns_current gauge\nfrps_proxy_conns_current{} {}\n",
                labels, stat.current_conns.load(Ordering::SeqCst)
            ));
            out.push_str(&format!(
                "# TYPE frps_proxy_conns_total counter\nfrps_proxy_conns_total{} {}\n",
                labels,
                stat.total_conns.load(Ordering::SeqCst)
            ));
        }
        out
    }
}

/// 进程级监控指标单例：供 Control::run 等深层调用点零参数获取，
/// 避免给已超长的构造参数链加参。Server::new 时注册。
static GLOBAL_METRICS: std::sync::OnceLock<std::sync::Arc<MonitorMetrics>> =
    std::sync::OnceLock::new();

fn set_global_metrics(metrics: std::sync::Arc<MonitorMetrics>) {
    let _ = GLOBAL_METRICS.set(metrics);
}

/// 获取全局监控指标（Server 尚未初始化时自动创建，用于单元测试等场景）
pub fn global_metrics() -> std::sync::Arc<MonitorMetrics> {
    GLOBAL_METRICS.get().cloned().unwrap_or_else(|| {
        let m = std::sync::Arc::new(MonitorMetrics::new());
        let _ = GLOBAL_METRICS.set(m.clone());
        m
    })
}

/// 控制器
pub struct Control {
    conn: ControlConn,
    run_id: String,
    user: String,
    client_id: String,
    proxy_manager: Arc<dyn ProxyManager + Send + Sync>,
    #[allow(dead_code)]
    visitor_manager: Arc<dyn VisitorManager + Send + Sync>,
    auth_manager: Arc<AuthManager>,
    /// 控制器管理器（用于注册客户端信息）
    control_manager: Arc<ControlManager>,
    last_heartbeat: Instant,
    registered_proxies: Vec<String>,
    /// 代理所有权映射 (proxy_name -> run_id)
    proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
    /// XTCP 访问者映射 (proxy_name -> visitor_run_id)
    xtcp_visitors: Arc<RwLock<std::collections::HashMap<String, String>>>,
    /// 登录成功通知通道
    login_tx: Option<mpsc::Sender<String>>,
    /// 消息发送通道（用于发送给客户端）
    msg_tx: Option<mpsc::Sender<Message>>,
    /// STCP 桥接管理器
    stcp_bridge_manager: Arc<StcpBridgeManager>,
    /// 工作连接管理器
    #[allow(dead_code)]
    work_conn_manager: Arc<ServerWorkConnManager>,
    /// 工作连接池大小（来自客户端 LoginMsg）
    pool_count: u32,
    /// 工作连接是否启用 TLS（通过 LoginRespMsg 协商给客户端）
    work_conn_tls: bool,
}

impl Control {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        conn: ControlConn,
        run_id: String,
        user: String,
        client_id: String,
        proxy_manager: Arc<dyn ProxyManager + Send + Sync>,
        visitor_manager: Arc<dyn VisitorManager + Send + Sync>,
        auth_manager: Arc<AuthManager>,
        control_manager: Arc<ControlManager>,
        proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
        xtcp_visitors: Arc<RwLock<std::collections::HashMap<String, String>>>,
        login_tx: Option<mpsc::Sender<String>>,
        msg_tx: Option<mpsc::Sender<Message>>,
        stcp_bridge_manager: Arc<StcpBridgeManager>,
        work_conn_manager: Arc<ServerWorkConnManager>,
        work_conn_tls: bool,
    ) -> Self {
        Self {
            conn,
            run_id,
            user,
            client_id,
            proxy_manager,
            visitor_manager,
            auth_manager,
            control_manager,
            last_heartbeat: Instant::now(),
            registered_proxies: Vec::new(),
            proxy_owners,
            xtcp_visitors,
            login_tx,
            msg_tx,
            stcp_bridge_manager,
            work_conn_manager,
            pool_count: 0, // 将在收到 LoginMsg 后由 run() 设置
            work_conn_tls,
        }
    }

    /// 发送消息到客户端（通过消息通道，供外部 visitor handler 调用）
    pub async fn send_msg(
        &self,
        msg: &Message,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(tx) = &self.msg_tx {
            tx.send(msg.clone()).await?;
            Ok(())
        } else {
            Err("Message channel not initialized".into())
        }
    }

    /// 清理该客户端注册的所有代理
    async fn cleanup_proxies(&self) {
        log::info!(
            "Client disconnected, cleaning up {} proxies",
            self.registered_proxies.len()
        );
        for proxy_name in &self.registered_proxies {
            log::info!("Removing proxy: {}", proxy_name);
            if let Err(e) = self.proxy_manager.remove_proxy(proxy_name).await {
                log::error!("Failed to remove proxy {}: {:?}", proxy_name, e);
            } else {
                log::info!("Removed proxy: {}", proxy_name);
            }
            global_metrics().remove_proxy_stat(proxy_name);
            // 清理代理所有权
            self.proxy_owners.write().await.remove(proxy_name);
        }
    }

    /// 写消息到客户端
    async fn write_msg(
        &mut self,
        msg: &Message,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.conn.write_message(msg).await
    }

    pub async fn run(
        &mut self,
        mut msg_rx: mpsc::Receiver<Message>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log::info!("Control::run started");
        // 读取登录消息
        let msg_result = self.conn.read_message().await;

        match msg_result {
            Ok(msg) => {
                match msg {
                    Message::Login(login_msg) => {
                        log::info!("Received login message from user: {}", login_msg.user);
                        // 验证登录
                        let verify_result = self
                            .auth_manager
                            .verify_login(&login_msg.user, &login_msg.token)
                            .await;
                        if let Err(e) = verify_result {
                            log::error!("Login verification failed: {:?}", e);
                            global_metrics().incr_login_failures();
                            return Err(format!("{:?}", e).into());
                        }
                        global_metrics().incr_login_successes();

                        // 更新控制器的信息
                        self.run_id = login_msg.run_id;
                        self.user = login_msg.user;
                        self.client_id = login_msg.client_id;
                        self.pool_count = login_msg.pool_count;

                        // 注册客户端信息到 ControlManager
                        self.control_manager
                            .add_client(
                                self.client_id.clone(),
                                self.run_id.clone(),
                                self.user.clone(),
                            )
                            .await;

                        // 发送登录响应（work_conn_tls 协商：服务器启用 TLS 时工作连接同步启用）
                        let resp = rust_frp_core::LoginRespMsg {
                            version: "0.1.0".to_string(),
                            run_id: self.run_id.clone(),
                            error: "".to_string(),
                            work_conn_tls: self.work_conn_tls,
                        };
                        let write_result = self.write_msg(&Message::LoginResp(resp)).await;
                        if let Err(e) = write_result {
                            log::error!("Failed to send login response: {:?}", e);
                            self.cleanup_proxies().await;
                            return Err(e);
                        }
                        log::info!("Sent login response to user: {}", self.user);

                        // 通知 handle_connection 登录成功
                        if let Some(tx) = self.login_tx.take() {
                            let _ = tx.send(self.run_id.clone()).await;
                        }

                        // 消息循环：使用 tokio::select! 同时处理读消息和发消息
                        // 参考 frp 的设计：同一个任务处理读写，无锁竞争
                        loop {
                            tokio::select! {
                                // 读取客户端消息（15秒读超时，用于心跳检测）
                                msg_result = tokio::time::timeout(Duration::from_secs(15), self.conn.read_message()) => {
                                    match msg_result {
                                        Ok(Ok(msg)) => {
                                            match msg {
                                                Message::Ping(ping_msg) => {
                                                    self.last_heartbeat = Instant::now();
                                                    let pong_msg = rust_frp_core::PongMsg {
                                                        timestamp: ping_msg.timestamp,
                                                    };
                                                    if let Err(e) = self.write_msg(&Message::Pong(pong_msg)).await {
                                                        log::error!("Failed to send pong message: {:?}", e);
                                                        self.cleanup_proxies().await;
                                                        return Err(e);
                                                    }
                                                }
                                                Message::RegisterProxy(register_proxy_msg) => {
                                                    let proxy = register_proxy_msg.proxy;
                                                    let proxy_name = proxy.name.clone();
                                                    let proxy_type = proxy.r#type.clone();
                                                    let proxy_remote_port = proxy.remote_port;
                                                    let result = self
                                                        .proxy_manager
                                                        .add_proxy_for_user(proxy, &self.user)
                                                        .await;

                                                    let error_msg = match result {
                                                        Ok(_) => {
                                                            self.registered_proxies.push(proxy_name.clone());
                                                            self.proxy_owners.write().await.insert(proxy_name.clone(), self.run_id.clone());
                                                            global_metrics().register_proxy_stat(&proxy_name, &proxy_type, proxy_remote_port);
                                                            "".to_string()
                                                        },
                                                        Err(e) => format!("{:?}", e),
                                                    };

                                                    let resp = rust_frp_core::RegisterProxyRespMsg {
                                                        name: proxy_name.clone(),
                                                        error: error_msg.clone(),
                                                    };

                                                    if let Err(e) = self.write_msg(&Message::RegisterProxyResp(resp)).await {
                                                        log::error!("Failed to send register proxy response: {:?}", e);
                                                        self.cleanup_proxies().await;
                                                        return Err(e);
                                                    }

                                                    if error_msg.is_empty() {
                                                        log::info!("proxy registered: {}", proxy_name);
                                                        // 初始化工作连接池（不做预填充，由 get_work_conn 的取后补充自然填充）
                                                        self.work_conn_manager.init_pool(&proxy_name).await;
                                                    } else {
                                                        log::error!("failed to register proxy {}: {}", proxy_name, error_msg);
                                                    }
                                                }
                                                Message::ProxyStatus(proxy_status_msg) => {
                                                    let status = self.proxy_manager.get_proxy_status(&proxy_status_msg.name).await
                                                        .map_err(|e| format!("{:?}", e))?;
                                                    let resp = rust_frp_core::ProxyStatusRespMsg {
                                                        name: proxy_status_msg.name,
                                                        status: status.unwrap_or_else(|| "unknown".to_string()),
                                                        error: "".to_string(),
                                                    };
                                                    if let Err(e) = self.write_msg(&Message::ProxyStatusResp(resp)).await {
                                                        log::error!("Failed to send proxy status response: {:?}", e);
                                                        self.cleanup_proxies().await;
                                                        return Err(e);
                                                    }
                                                }
                                                Message::Disconnect(disconnect_msg) => {
                                                    log::info!("Received disconnect message from client: reason={}", disconnect_msg.reason);
                                                    self.cleanup_proxies().await;
                                                    log::info!("Control::run finished (graceful disconnect)");
                                                    return Ok(());
                                                }
                                                Message::UdpPacket(udp_msg) => {
                                                    if let Some(addr) = &udp_msg.client_addr {
                                                        if let Err(e) = self.proxy_manager.send_udp_packet(
                                                            &udp_msg.proxy_name,
                                                            &udp_msg.data,
                                                            addr,
                                                        ).await {
                                                            log::error!("Failed to send UDP packet to visitor: {:?}", e);
                                                        }
                                                    }
                                                }
                                                Message::StcpVisitor(stcp_msg) => {
                                                    log::info!(
                                                        "Received STCP visitor request for proxy {} from client {}",
                                                        stcp_msg.proxy_name,
                                                        self.run_id
                                                    );

                                                    let proxy_name = stcp_msg.proxy_name.clone();
                                                    let visitor_run_id = self.run_id.clone();

                                                    let proxy_run_id = {
                                                        let owners = self.proxy_owners.read().await;
                                                        owners.get(&proxy_name).cloned()
                                                    };

                                                    let proxy_run_id = match proxy_run_id {
                                                        Some(id) => id,
                                                        None => {
                                                            log::error!("No proxy owner found for STCP: {}", proxy_name);
                                                            let resp = StcpVisitorRespMsg {
                                                                proxy_name: proxy_name.clone(),
                                                                error: "proxy not found".to_string(),
                                                                visitor_run_id: visitor_run_id.clone(),
                                                            };
                                                            if let Err(e) = self.write_msg(&Message::StcpVisitorResp(resp)).await {
                                                                log::error!("Failed to send StcpVisitorResp: {:?}", e);
                                                            }
                                                            continue;
                                                        }
                                                    };

                                                    if proxy_run_id == visitor_run_id {
                                                        self.stcp_bridge_manager.create_bridge(
                                                            proxy_name.clone()
                                                        ).await;

                                                        let msg_tx_proxy = self.control_manager.get_msg_tx(&proxy_run_id).await;
                                                        let msg_tx_visitor = self.control_manager.get_msg_tx(&visitor_run_id).await;

                                                        if let Some(tx) = &msg_tx_proxy {
                                                            let req = ReqWorkConnMsg {
                                                                proxy_name: proxy_name.clone(),
                                                            };
                                                            if let Err(e) = tx.send(Message::ReqWorkConn(req)).await {
                                                                log::error!("Failed to send ReqWorkConn to proxy: {:?}", e);
                                                            }
                                                        }

                                                        if let Some(tx) = &msg_tx_visitor {
                                                            let req = ReqWorkConnMsg {
                                                                proxy_name: proxy_name.clone(),
                                                            };
                                                            if let Err(e) = tx.send(Message::ReqWorkConn(req)).await {
                                                                log::error!("Failed to send ReqWorkConn to visitor: {:?}", e);
                                                            }
                                                        }

                                                        let resp = StcpVisitorRespMsg {
                                                            proxy_name: proxy_name.clone(),
                                                            error: String::new(),
                                                            visitor_run_id: visitor_run_id.clone(),
                                                        };
                                                        if let Err(e) = self.write_msg(&Message::StcpVisitorResp(resp)).await {
                                                            log::error!("Failed to send StcpVisitorResp: {:?}", e);
                                                        }
                                                    } else {
                                                        log::error!("STCP proxy {} owned by another client", proxy_name);
                                                        let resp = StcpVisitorRespMsg {
                                                            proxy_name: proxy_name.clone(),
                                                            error: "proxy owned by another client".to_string(),
                                                            visitor_run_id,
                                                        };
                                                        if let Err(e) = self.write_msg(&Message::StcpVisitorResp(resp)).await {
                                                            log::error!("Failed to send StcpVisitorResp: {:?}", e);
                                                        }
                                                    }
                                                }
                                                Message::XtcpNatInfo(xtcp_msg) => {
                                                    log::info!(
                                                        "Received XTCP NAT info for proxy {} from {}",
                                                        xtcp_msg.proxy_name,
                                                        self.run_id
                                                    );

                                                    let proxy_name = xtcp_msg.proxy_name.clone();
                                                    let from_run_id = self.run_id.clone();

                                                    let owner_run_id = {
                                                        let owners = self.proxy_owners.read().await;
                                                        owners.get(&proxy_name).cloned()
                                                    };

                                                    let owner_run_id = match owner_run_id {
                                                        Some(id) => id,
                                                        None => {
                                                            log::error!("No proxy owner found for XTCP: {}", proxy_name);
                                                            continue;
                                                        }
                                                    };

                                                    let relay = XtcpNatInfoMsg {
                                                        proxy_name: proxy_name.clone(),
                                                        run_id: from_run_id.clone(),
                                                        nat_type: xtcp_msg.nat_type.clone(),
                                                        local_addr: xtcp_msg.local_addr.clone(),
                                                        public_addr: xtcp_msg.public_addr.clone(),
                                                    };

                                                    if from_run_id != owner_run_id {
                                                        // 来自 visitor，存储 visitor run_id 并中继给 proxy owner
                                                        {
                                                            let mut visitors = self.xtcp_visitors.write().await;
                                                            visitors.insert(proxy_name.clone(), from_run_id.clone());
                                                        }
                                                        log::info!("XTCP visitor registered: {} -> {}", proxy_name, from_run_id);

                                                        let target_tx = self.control_manager.get_msg_tx(&owner_run_id).await;
                                                        if let Some(tx) = &target_tx {
                                                            if let Err(e) = tx.send(Message::XtcpNatInfo(relay)).await {
                                                                log::error!("Failed to relay XTCP NAT info to owner: {:?}", e);
                                                            }
                                                        }
                                                    } else {
                                                        // 来自 proxy owner，中继给 visitor
                                                        let visitor_run_id = {
                                                            let visitors = self.xtcp_visitors.read().await;
                                                            visitors.get(&proxy_name).cloned()
                                                        };

                                                        match visitor_run_id {
                                                            Some(vid) => {
                                                                let target_tx = self.control_manager.get_msg_tx(&vid).await;
                                                                if let Some(tx) = &target_tx {
                                                                    if let Err(e) = tx.send(Message::XtcpNatInfo(relay)).await {
                                                                        log::error!("Failed to relay XTCP NAT info to visitor: {:?}", e);
                                                                    } else {
                                                                        log::info!("Relayed XTCP NAT info from owner {} to visitor {}", from_run_id, vid);
                                                                    }
                                                                }
                                                            }
                                                            None => {
                                                                log::info!("No XTCP visitor yet for proxy {}, NAT info from owner stored", proxy_name);
                                                            }
                                                        }
                                                    }
                                                }
                                                Message::XtcpHolePunch(hp_msg) => {
                                                    let to_run_id = hp_msg.to_run_id.clone();
                                                    let relay = XtcpHolePunchMsg {
                                                        proxy_name: hp_msg.proxy_name.clone(),
                                                        from_run_id: hp_msg.from_run_id.clone(),
                                                        to_run_id: to_run_id.clone(),
                                                        peer_local_addr: hp_msg.peer_local_addr.clone(),
                                                        peer_public_addr: hp_msg.peer_public_addr.clone(),
                                                    };

                                                    let target_tx = self.control_manager.get_msg_tx(&to_run_id).await;
                                                    if let Some(tx) = &target_tx {
                                                        if let Err(e) = tx.send(Message::XtcpHolePunch(relay)).await {
                                                            log::error!("Failed to relay XTCP hole punch: {:?}", e);
                                                        }
                                                    }
                                                }
                                                _ => {
                                                    log::warn!("unexpected message in loop: {:?}", msg);
                                                }
                                            }
                                        }
                                        Ok(Err(e)) => {
                                            log::warn!("Client connection closed unexpectedly: {:?}", e);
                                            self.cleanup_proxies().await;
                                            return Ok(());
                                        }
                                        Err(_elapsed) => {
                                            if self.last_heartbeat.elapsed() > Duration::from_secs(90) {
                                                log::warn!(
                                                    "Heartbeat timeout for client {} (no ping for {:?}), cleaning up proxies",
                                                    self.run_id,
                                                    self.last_heartbeat.elapsed()
                                                );
                                                self.cleanup_proxies().await;
                                                return Ok(());
                                            }
                                        }
                                    }
                                },
                                // 接收要发送的消息（来自 visitor handler）
                                msg = msg_rx.recv() => {
                                    match msg {
                                        Some(msg_to_send) => {
                                            if let Err(e) = self.write_msg(&msg_to_send).await {
                                                log::error!("Failed to send message via channel: {:?}", e);
                                            }
                                        }
                                        None => {
                                            log::warn!("Message sender dropped, exiting loop");
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        log::warn!("unexpected first message: {:?}", msg);
                        return Err("Unexpected first message".into());
                    }
                }
            }
            Err(e) => {
                log::error!("read login message error: {:?}", e);
                self.cleanup_proxies().await;
                log::info!("Control::run finished");
                return Err(e);
            }
        }

        Ok(())
    }
}

/// 控制器管理器
/// 客户端连接信息
#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub run_id: String,
    pub client_id: String,
    pub user: String,
    pub connected_at: Instant,
    pub last_heartbeat: Instant,
}

pub struct ControlManager {
    // 存储 run_id -> msg_tx 映射，用于向客户端发送消息
    msg_channels: RwLock<std::collections::HashMap<String, mpsc::Sender<Message>>>,
    // 存储客户端连接信息 (run_id -> ClientInfo)
    clients: RwLock<std::collections::HashMap<String, ClientInfo>>,
}

impl Default for ControlManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlManager {
    pub fn new() -> Self {
        Self {
            msg_channels: RwLock::new(std::collections::HashMap::new()),
            clients: RwLock::new(std::collections::HashMap::new()),
        }
    }

    pub async fn add(
        &self,
        run_id: String,
        msg_tx: mpsc::Sender<Message>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut msg_channels = self.msg_channels.write().await;
        msg_channels.insert(run_id.clone(), msg_tx);
        Ok(())
    }

    pub async fn remove(
        &self,
        run_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut msg_channels = self.msg_channels.write().await;
        msg_channels.remove(run_id);

        let mut clients = self.clients.write().await;
        clients.remove(run_id);
        Ok(())
    }

    pub async fn get_msg_tx(&self, run_id: &str) -> Option<mpsc::Sender<Message>> {
        let msg_channels = self.msg_channels.read().await;
        msg_channels.get(run_id).cloned()
    }

    /// 添加或更新客户端信息
    pub async fn add_client(&self, client_id: String, run_id: String, user: String) {
        let now = Instant::now();
        let mut clients = self.clients.write().await;
        clients.insert(
            run_id.clone(),
            ClientInfo {
                run_id,
                client_id,
                user,
                connected_at: now,
                last_heartbeat: now,
            },
        );
    }

    /// 更新客户端心跳时间
    pub async fn update_heartbeat(&self, run_id: &str) {
        let mut clients = self.clients.write().await;
        if let Some(client) = clients.get_mut(run_id) {
            client.last_heartbeat = Instant::now();
        }
    }

    /// 获取所有客户端列表
    pub async fn get_clients(&self) -> Vec<ClientInfo> {
        let clients = self.clients.read().await;
        clients.values().cloned().collect()
    }
}

/// STCP 桥接状态，用于等待两个客户端的工连接并桥接
struct StcpBridgeState {
    conn1: Option<AnyConn>,
    conn2: Option<AnyConn>,
}

/// STCP 桥接管理器，用于协调两个客户端的工作连接
pub struct StcpBridgeManager {
    bridges: RwLock<std::collections::HashMap<String, StcpBridgeState>>,
}

impl Default for StcpBridgeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl StcpBridgeManager {
    pub fn new() -> Self {
        Self {
            bridges: RwLock::new(std::collections::HashMap::new()),
        }
    }

    pub async fn create_bridge(&self, bridge_id: String) {
        let mut bridges = self.bridges.write().await;
        bridges.insert(
            bridge_id,
            StcpBridgeState {
                conn1: None,
                conn2: None,
            },
        );
    }

    /// 添加连接并尝试桥接。
    /// 返回 Some((c1, c2)) 表示桥接已就绪
    /// 返回 None 表示连接已存储（等待另一半）
    /// 返回 Err 表示没有此桥接（连接未消耗）
    pub async fn add_conn_and_try_bridge(
        &self,
        bridge_id: &str,
        conn: AnyConn,
    ) -> Result<Option<(AnyConn, AnyConn)>, AnyConn> {
        let mut bridges = self.bridges.write().await;
        if let Some(state) = bridges.get_mut(bridge_id) {
            if state.conn1.is_none() {
                state.conn1 = Some(conn);
                Ok(None)
            } else if state.conn2.is_none() {
                state.conn2 = Some(conn);
                let mut state = bridges.remove(bridge_id).unwrap();
                let c1 = state.conn1.take().unwrap();
                let c2 = state.conn2.take().unwrap();
                Ok(Some((c1, c2)))
            } else {
                Ok(None)
            }
        } else {
            Err(conn)
        }
    }

    pub async fn cleanup(&self, bridge_id: &str) {
        let mut bridges = self.bridges.write().await;
        bridges.remove(bridge_id);
    }
}

/// 服务器代理管理器
type ListenerMap = Arc<
    RwLock<
        std::collections::HashMap<
            String,
            (
                std::sync::Arc<tokio::net::TcpListener>,
                std::sync::Arc<std::sync::atomic::AtomicBool>,
            ),
        >,
    >,
>;

/// UDP 代理会话信息，用于跟踪访问者地址以便回传响应
#[derive(Debug, Clone)]
struct UdpProxySession {
    socket: Arc<tokio::net::UdpSocket>,
    running: Arc<std::sync::atomic::AtomicBool>,
}

type UdpSocketMap = Arc<RwLock<std::collections::HashMap<String, UdpProxySession>>>;

/// 组共享监听器在 listeners / accept_handles 中的键（与代理名空间隔离）
fn group_listener_key(port: u16) -> String {
    format!("__group_port_{}__", port)
}

/// TCP 代理负载均衡分组状态
struct GroupState {
    /// 组名
    group: String,
    /// 组密钥（加入时校验，防止误入他人分组）
    group_key: String,
    /// 成员代理名（注册顺序）
    members: Vec<String>,
    /// round-robin 轮询索引
    rr_index: usize,
}

/// TCP 代理负载均衡分组注册表
///
/// 同 group + 同 remote_port 的代理共享一个监听端口：
/// 首成员绑定端口并启动 accept 循环，后续成员仅注册成员身份；
/// 新连接按 round-robin 选取成员处理（对齐 frp group 语义）。
///
/// 组名全局唯一（同名组不允许绑定不同端口）。
#[derive(Default)]
pub struct GroupRegistry {
    /// 端口 -> 组状态
    groups: RwLock<std::collections::HashMap<u16, GroupState>>,
    /// 组名 -> 端口（组名唯一性索引）
    group_ports: RwLock<std::collections::HashMap<String, u16>>,
}

impl GroupRegistry {
    fn new() -> Self {
        Self::default()
    }

    /// 加入组；返回 `true` 表示本代理是首成员（需要绑定监听端口）
    ///
    /// 错误场景（对齐 frp ErrGroupAuthFailed / ErrGroupDifferentPort）：
    /// - 同组名绑定不同端口
    /// - 同端口已被其他组占用
    /// - group_key 与已有成员不匹配
    pub async fn join(
        &self,
        group: &str,
        group_key: &str,
        port: u16,
        proxy_name: &str,
    ) -> Result<bool, String> {
        // 组名唯一性：同组名不允许绑定不同端口
        {
            let group_ports = self.group_ports.read().await;
            if let Some(&bound) = group_ports.get(group) {
                if bound != port {
                    return Err(format!(
                        "group [{}] is bound to port {}, cannot join port {}",
                        group, bound, port
                    ));
                }
            }
        }

        let mut groups = self.groups.write().await;
        match groups.get_mut(&port) {
            Some(state) => {
                if state.group != group {
                    return Err(format!(
                        "port {} is already bound by group [{}]",
                        port, state.group
                    ));
                }
                if state.group_key != group_key {
                    return Err(format!(
                        "group [{}] auth failed: group_key mismatch",
                        group
                    ));
                }
                state.members.push(proxy_name.to_string());
                log::info!(
                    "proxy [{}] joined group [{}] on port {} ({} members)",
                    proxy_name,
                    group,
                    port,
                    state.members.len()
                );
                Ok(false)
            }
            None => {
                groups.insert(
                    port,
                    GroupState {
                        group: group.to_string(),
                        group_key: group_key.to_string(),
                        members: vec![proxy_name.to_string()],
                        rr_index: 0,
                    },
                );
                self.group_ports
                    .write()
                    .await
                    .insert(group.to_string(), port);
                log::info!(
                    "proxy [{}] is first member of group [{}] on port {}",
                    proxy_name,
                    group,
                    port
                );
                Ok(true)
            }
        }
    }

    /// 退出组；返回 `true` 表示组已空（应关闭共享监听器）
    pub async fn leave(&self, port: u16, proxy_name: &str) -> bool {
        let mut groups = self.groups.write().await;
        let empty = match groups.get_mut(&port) {
            Some(state) => {
                state.members.retain(|m| m != proxy_name);
                state.members.is_empty()
            }
            None => false,
        };
        if empty {
            if let Some(state) = groups.remove(&port) {
                self.group_ports.write().await.remove(&state.group);
                log::info!("group [{}] on port {} is empty", state.group, port);
            }
        }
        empty
    }

    /// round-robin 选取一个成员处理新连接
    pub async fn pick(&self, port: u16) -> Option<String> {
        let mut groups = self.groups.write().await;
        let state = groups.get_mut(&port)?;
        if state.members.is_empty() {
            return None;
        }
        let name = state.members[state.rr_index % state.members.len()].clone();
        state.rr_index = state.rr_index.wrapping_add(1);
        Some(name)
    }

    /// 组当前成员数（日志/调试用）
    pub async fn member_count(&self, port: u16) -> usize {
        self.groups
            .read()
            .await
            .get(&port)
            .map(|s| s.members.len())
            .unwrap_or(0)
    }
}

pub struct ServerProxyManager {
    proxies: RwLock<std::collections::HashMap<String, rust_frp_config::ProxyConfig>>,
    listeners: ListenerMap,
    udp_sessions: UdpSocketMap,
    http_vhost_router: Arc<HttpVhostRouter>,
    /// 代理所有权映射 (proxy_name -> run_id)
    proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
    /// 控制器管理器
    control_manager: Arc<ControlManager>,
    /// 工作连接管理器
    work_conn_manager: Arc<ServerWorkConnManager>,
    /// 认证管理器（用于生成 sign_key）
    auth_manager: Arc<AuthManager>,
    /// 允许的端口列表（空列表 = 默认拒绝所有）
    allow_ports: Vec<rust_frp_config::PortRange>,
    /// 单用户最大端口配额（None = 不限制，对应 max_ports_per_user 配置）
    max_ports_per_user: Option<usize>,
    /// 用户已占用端口计数 (user -> ports_used)
    user_port_counts: RwLock<std::collections::HashMap<String, usize>>,
    /// 代理归属与端口占用记录 (proxy_name -> (user, ports_used))，用于移除时释放配额
    proxy_user_ports: RwLock<std::collections::HashMap<String, (String, usize)>>,
    /// accept 任务的 JoinHandle，用于 stop_proxy 时立即中止
    accept_handles: RwLock<std::collections::HashMap<String, tokio::task::JoinHandle<()>>>,
    /// TCP 负载均衡分组注册表（group 代理共享监听端口，round-robin 分发）
    group_registry: Arc<GroupRegistry>,
}

/// 检查端口是否在允许列表中
fn port_allowed(port: u16, ranges: &[rust_frp_config::PortRange]) -> bool {
    if ranges.is_empty() {
        return false;
    }
    for range in ranges {
        // 单端口匹配
        if let Some(single) = range.single {
            if port == single {
                return true;
            }
        }
        // 范围匹配：start/end 均显式配置时才按范围判定。
        // 修复：此前 start/end 缺省 0/65535，导致 { single = x } 条目
        // 实际放行全部端口，白名单形同虚设。
        if let (Some(start), Some(end)) = (range.start, range.end) {
            if port >= start && port <= end {
                return true;
            }
        }
    }
    false
}

/// 工作连接首字节分类结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkConnClass {
    /// 客户端发起 TLS 握手（首字节 0x16）且服务器已配置 TLS
    Tls,
    /// 明文协议（兼容旧客户端）
    Plain,
    /// 拒绝连接
    Reject,
}

/// 根据首字节判定工作连接处理方式
///
/// - `first_byte == 0x16`：TLS ClientHello，服务器配置了 TLS 则走 TLS，
///   未配置则无法完成握手只能拒绝
/// - 其他字节：明文协议；tls_only 模式下拒绝（防止降级）
pub fn classify_work_conn(first_byte: u8, tls_available: bool, tls_only: bool) -> WorkConnClass {
    match (first_byte == 0x16, tls_available, tls_only) {
        (true, true, _) => WorkConnClass::Tls,
        (true, false, _) => WorkConnClass::Reject,
        (false, _, true) => WorkConnClass::Reject,
        (false, _, false) => WorkConnClass::Plain,
    }
}

/// 工作连接错误日志（对端断开类错误降级为 debug，避免日志噪音）
fn log_work_conn_error(e: &Box<dyn std::error::Error + Send + Sync>) {
    let msg = e.to_string().to_lowercase();
    if msg.contains("connection reset")
        || msg.contains("connection aborted")
        || msg.contains("broken pipe")
    {
        log::debug!("Work connection closed (peer disconnected): {:?}", e);
    } else {
        log::error!("Failed to process work connection: {:?}", e);
    }
}

impl ServerProxyManager {
    pub fn new(
        http_vhost_router: Arc<HttpVhostRouter>,
        proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
        control_manager: Arc<ControlManager>,
        work_conn_manager: Arc<ServerWorkConnManager>,
        auth_manager: Arc<AuthManager>,
        allow_ports: Vec<rust_frp_config::PortRange>,
        max_ports_per_user: Option<usize>,
    ) -> Self {
        if allow_ports.is_empty() {
            log::warn!(
                "allow_ports is empty, all TCP proxy ports will be rejected. \
                 Please configure allow_ports in frps.toml to specify allowed port ranges."
            );
        }
        Self {
            proxies: RwLock::new(std::collections::HashMap::new()),
            listeners: Arc::new(RwLock::new(std::collections::HashMap::new())),
            udp_sessions: Arc::new(RwLock::new(std::collections::HashMap::new())),
            http_vhost_router,
            proxy_owners,
            control_manager,
            work_conn_manager,
            auth_manager,
            allow_ports,
            max_ports_per_user,
            user_port_counts: RwLock::new(std::collections::HashMap::new()),
            proxy_user_ports: RwLock::new(std::collections::HashMap::new()),
            accept_handles: RwLock::new(std::collections::HashMap::new()),
            group_registry: Arc::new(GroupRegistry::new()),
        }
    }

    pub async fn start_proxy(
        &self,
        config: &rust_frp_config::ProxyConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match config.r#type.as_str() {
            "tcp" => {
                if let Some(remote_port) = config.remote_port {
                    // 检查端口是否在允许列表中（空列表 = 默认拒绝所有）
                    if !port_allowed(remote_port, &self.allow_ports) {
                        return Err(format!(
                            "Port {} is not in the allowed ports list",
                            remote_port
                        )
                        .into());
                    }

                    // 负载均衡分组：加入组；首成员绑定端口，后续成员共享监听器
                    let group_port = if let Some(ref group) = config.group {
                        let group_key = config.group_key.clone().unwrap_or_default();
                        let first = self
                            .group_registry
                            .join(group, &group_key, remote_port, &config.name)
                            .await
                            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
                        if !first {
                            // 共享已有监听器，本成员无需绑定
                            return Ok(());
                        }
                        Some(remote_port)
                    } else {
                        None
                    };

                    let addr = format!("0.0.0.0:{}", remote_port).parse::<SocketAddr>()?;
                    let listener = tokio::net::TcpListener::bind(&addr).await?;
                    let proxy_name = config.name.clone();
                    let listeners = self.listeners.clone();

                    // 使用Arc来共享listener
                    let listener_arc = std::sync::Arc::new(listener);
                    let listener_clone = listener_arc.clone();

                    // 创建一个原子布尔值来控制任务的运行
                    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
                    let running_clone = running.clone();

                    // 共享状态用于工作连接协议
                    let proxy_owners = self.proxy_owners.clone();
                    let control_manager = self.control_manager.clone();
                    let work_conn_manager = self.work_conn_manager.clone();
                    let auth_manager = self.auth_manager.clone();
                    let plugin_config = config.plugin.clone();
                    // 分组分发：accept 循环内 round-robin 选取成员
                    let group_registry = self.group_registry.clone();

                    let handle = tokio::spawn(async move {
                        while running_clone.load(std::sync::atomic::Ordering::Relaxed) {
                            match listener_clone.accept().await {
                                Ok((visitor_conn, visitor_addr)) => {
                                    log::info!(
                                        "new TCP connection for proxy {} from {}",
                                        proxy_name,
                                        visitor_addr
                                    );

                                    let proxy_name_clone = proxy_name.clone();
                                    let proxy_owners = proxy_owners.clone();
                                    let control_manager = control_manager.clone();
                                    let work_conn_manager = work_conn_manager.clone();
                                    let auth_manager = auth_manager.clone();
                                    let _ = &auth_manager;
                                    let plugin_config = plugin_config.clone();
                                    let group_registry = group_registry.clone();

                                    tokio::spawn(async move {
                                        log::debug!("开始处理外部连接: proxy={}", proxy_name_clone);

                                        // 负载均衡分组：round-robin 选取实际处理连接的成员
                                        let target_name = if let Some(port) = group_port {
                                            match group_registry.pick(port).await {
                                                Some(name) => {
                                                    log::debug!(
                                                        "group port {} picked member [{}] (connection from {})",
                                                        port,
                                                        name,
                                                        visitor_addr
                                                    );
                                                    name
                                                }
                                                None => {
                                                    log::error!(
                                                        "group on port {} has no available members",
                                                        port
                                                    );
                                                    let _ = visitor_conn.try_write(b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 29\r\n\r\nNo available group members");
                                                    return;
                                                }
                                            }
                                        } else {
                                            proxy_name_clone.clone()
                                        };

                                        // per-proxy 连接统计守卫（drop 时自动减一，按实际服务成员计）
                                        let _conn_guard = global_metrics()
                                            .get_proxy_stat(&target_name)
                                            .map(ProxyConnGuard::acquire);

                                        // 检查是否有插件配置（插件直接处理访问者连接，不需要工作连接）
                                        if let Some(ref pconf) = plugin_config {
                                            log::debug!(
                                                "使用插件处理连接: proxy={}",
                                                proxy_name_clone
                                            );
                                            let plugin_mgr = rust_frp_plugin::PluginManager::new();
                                            match plugin_mgr.create_plugin(pconf) {
                                                Ok(mut plugin) => {
                                                    if let Err(e) =
                                                        plugin.handle(Box::new(visitor_conn)).await
                                                    {
                                                        log::error!("Plugin handle error for proxy {}: {:?}", proxy_name_clone, e);
                                                    }
                                                }
                                                Err(e) => {
                                                    log::error!("Failed to create plugin for proxy {}: {:?}", proxy_name_clone, e);
                                                }
                                            }
                                            return;
                                        }

                                        log::debug!(
                                            "使用工作连接协议处理: proxy={}",
                                            target_name
                                        );

                                        // 1. 查找代理对应的 run_id
                                        let run_id = {
                                            let owners = proxy_owners.read().await;
                                            owners.get(&target_name).cloned()
                                        };

                                        log::debug!(
                                            "查找代理所有者: proxy={}, found={}",
                                            target_name,
                                            run_id.is_some()
                                        );

                                        let run_id = match run_id {
                                            Some(id) => id,
                                            None => {
                                                log::error!(
                                                    "No owner found for proxy: {}",
                                                    target_name
                                                );
                                                let _ = visitor_conn.try_write(b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 30\r\n\r\nProxy not registered by any client");
                                                return;
                                            }
                                        };

                                        log::debug!(
                                            "找到代理所有者: proxy={}, run_id={}",
                                            target_name,
                                            run_id
                                        );

                                        // 2. 获取对应的消息通道
                                        let msg_tx = match control_manager.get_msg_tx(&run_id).await
                                        {
                                            Some(tx) => tx,
                                            None => {
                                                log::error!(
                                                    "Message channel not found for run_id: {}",
                                                    run_id
                                                );
                                                let _ = visitor_conn.try_write(b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 37\r\n\r\nMessage channel not found");
                                                return;
                                            }
                                        };

                                        log::debug!(
                                            "找到消息通道: proxy={}, run_id={}",
                                            target_name,
                                            run_id
                                        );

                                        // 3. 从池中获取工作连接（池为空时会自动请求）
                                        match work_conn_manager
                                            .get_work_conn(
                                                &target_name,
                                                &msg_tx,
                                                Duration::from_secs(30),
                                                visitor_addr,
                                            )
                                            .await
                                        {
                                            Ok(work_conn) => {
                                                log::info!("Got work conn for proxy {}, bridging with visitor", target_name);
                                                if let Err(e) = rust_frp_util::bridge_streams(
                                                    visitor_conn,
                                                    work_conn,
                                                )
                                                .await
                                                {
                                                    log::error!(
                                                        "Bridge error for proxy {}: {:?}",
                                                        target_name,
                                                        e
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                log::error!(
                                                    "Failed to get work conn for {}: {}",
                                                    target_name,
                                                    e
                                                );
                                                let _ = visitor_conn.try_write(
                                                    b"HTTP/1.1 504 Gateway Timeout\r\n\r\n",
                                                );
                                            }
                                        }
                                    });
                                }
                                Err(e) => {
                                    log::error!("accept TCP connection error: {:?}", e);
                                    break;
                                }
                            }
                        }
                        log::info!("TCP proxy {} stopped", proxy_name);
                    });

                    // 分组代理的监听器按组端口键存储（与代理名空间隔离，
                    // 成员进出不影响共享监听器；组空时由 stop_proxy 清理）
                    let listener_key = match group_port {
                        Some(port) => group_listener_key(port),
                        None => config.name.clone(),
                    };
                    let mut listeners = listeners.write().await;
                    listeners.insert(listener_key.clone(), (listener_arc, running));
                    let mut handles = self.accept_handles.write().await;
                    handles.insert(listener_key, handle);
                }
            }
            "http" => {
                // HTTP 代理 - 注册到虚拟主机路由器
                let mut domains = Vec::new();

                // 添加自定义域名
                if let Some(custom_domains) = &config.custom_domains {
                    domains.extend(custom_domains.clone());
                }

                // 添加子域名
                if let Some(subdomain) = &config.subdomain {
                    // 这里可以配置基础域名，例如: subdomain.example.com
                    domains.push(subdomain.clone());
                }

                if !domains.is_empty() {
                    self.http_vhost_router
                        .register_proxy(config.name.clone(), domains, config.clone())
                        .await;
                    log::info!(
                        "HTTP proxy {} registered with domains: {:?}",
                        config.name,
                        config.custom_domains
                    );
                } else {
                    log::warn!("HTTP proxy {} has no domains configured", config.name);
                }
            }
            "https" => {
                // HTTPS 代理 - 类似于 HTTP，但需要 TLS 处理
                let mut domains = Vec::new();

                if let Some(custom_domains) = &config.custom_domains {
                    domains.extend(custom_domains.clone());
                }

                if let Some(subdomain) = &config.subdomain {
                    domains.push(subdomain.clone());
                }

                if !domains.is_empty() {
                    self.http_vhost_router
                        .register_proxy(config.name.clone(), domains, config.clone())
                        .await;
                    log::info!(
                        "HTTPS proxy {} registered with domains: {:?}",
                        config.name,
                        config.custom_domains
                    );
                }
            }
            "udp" => {
                if let Some(remote_port) = config.remote_port {
                    if !port_allowed(remote_port, &self.allow_ports) {
                        return Err(format!(
                            "Port {} is not in the allowed ports list",
                            remote_port
                        )
                        .into());
                    }
                    let addr = format!("0.0.0.0:{}", remote_port).parse::<SocketAddr>()?;
                    let socket = tokio::net::UdpSocket::bind(&addr).await?;
                    let socket = Arc::new(socket);
                    let socket_clone = socket.clone();
                    let proxy_name = config.name.clone();
                    let proxy_owners = self.proxy_owners.clone();
                    let control_manager = self.control_manager.clone();
                    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
                    let running_clone = running.clone();

                    self.udp_sessions.write().await.insert(
                        config.name.clone(),
                        UdpProxySession {
                            socket: socket.clone(),
                            running: running.clone(),
                        },
                    );

                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 65535];
                        while running_clone.load(std::sync::atomic::Ordering::Relaxed) {
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(1),
                                socket_clone.recv_from(&mut buf),
                            )
                            .await
                            {
                                Ok(Ok((n, src_addr))) => {
                                    let data = buf[..n].to_vec();
                                    let run_id = {
                                        let owners = proxy_owners.read().await;
                                        owners.get(&proxy_name).cloned()
                                    };
                                    if let Some(run_id) = run_id {
                                        if let Some(msg_tx) =
                                            control_manager.get_msg_tx(&run_id).await
                                        {
                                            let udp_msg = rust_frp_core::UdpPacketMsg {
                                                proxy_name: proxy_name.clone(),
                                                data,
                                                client_addr: Some(src_addr.to_string()),
                                            };
                                            let _ = msg_tx.send(Message::UdpPacket(udp_msg)).await;
                                        }
                                    }
                                }
                                Ok(Err(e)) => {
                                    log::error!("UDP recv error for proxy {}: {:?}", proxy_name, e);
                                    break;
                                }
                                Err(_) => {
                                    continue;
                                }
                            }
                        }
                        log::info!("UDP proxy {} stopped", proxy_name);
                    });

                    log::info!("UDP proxy {} listening on {}", config.name, addr);
                } else {
                    return Err("UDP proxy requires remote_port".into());
                }
            }
            "websocket" => {
                if let Some(remote_port) = config.remote_port {
                    if !port_allowed(remote_port, &self.allow_ports) {
                        return Err(format!(
                            "Port {} is not in the allowed ports list",
                            remote_port
                        )
                        .into());
                    }
                    let addr = format!("0.0.0.0:{}", remote_port).parse::<SocketAddr>()?;
                    let listener = tokio::net::TcpListener::bind(&addr).await?;
                    let proxy_name = config.name.clone();
                    let listeners = self.listeners.clone();
                    let listener_arc = std::sync::Arc::new(listener);
                    let listener_clone = listener_arc.clone();
                    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
                    let running_clone = running.clone();
                    let proxy_owners = self.proxy_owners.clone();
                    let control_manager = self.control_manager.clone();
                    let work_conn_manager = self.work_conn_manager.clone();
                    let auth_manager = self.auth_manager.clone();

                    let handle = tokio::spawn(async move {
                        while running_clone.load(std::sync::atomic::Ordering::Relaxed) {
                            match listener_clone.accept().await {
                                Ok((visitor_conn, visitor_addr)) => {
                                    log::info!(
                                        "new WebSocket connection for proxy {} from {}",
                                        proxy_name,
                                        visitor_addr
                                    );

                                    let proxy_name_clone = proxy_name.clone();
                                    let proxy_owners = proxy_owners.clone();
                                    let control_manager = control_manager.clone();
                                    let work_conn_manager = work_conn_manager.clone();
                                    let _auth_manager = auth_manager.clone();

                                    tokio::spawn(async move {
                                        // per-proxy 连接统计守卫（drop 时自动减一）
                                        let _conn_guard = global_metrics()
                                            .get_proxy_stat(&proxy_name_clone)
                                            .map(ProxyConnGuard::acquire);
                                        let ws_stream = match accept_async(visitor_conn).await {
                                            Ok(ws) => ws,
                                            Err(e) => {
                                                log::error!(
                                                    "WebSocket upgrade failed for proxy {}: {:?}",
                                                    proxy_name_clone,
                                                    e
                                                );
                                                return;
                                            }
                                        };

                                        let run_id = {
                                            let owners = proxy_owners.read().await;
                                            owners.get(&proxy_name_clone).cloned()
                                        };

                                        let run_id = match run_id {
                                            Some(id) => id,
                                            None => {
                                                log::error!(
                                                    "No owner found for proxy: {}",
                                                    proxy_name_clone
                                                );
                                                return;
                                            }
                                        };

                                        let msg_tx = match control_manager.get_msg_tx(&run_id).await
                                        {
                                            Some(tx) => tx,
                                            None => {
                                                log::error!(
                                                    "Message channel not found for run_id: {}",
                                                    run_id
                                                );
                                                return;
                                            }
                                        };

                                        // 从池中获取工作连接
                                        match work_conn_manager
                                            .get_work_conn(
                                                &proxy_name_clone,
                                                &msg_tx,
                                                Duration::from_secs(30),
                                                visitor_addr,
                                            )
                                            .await
                                        {
                                            Ok(work_conn) => {
                                                log::info!("Got work conn for WebSocket proxy {}, bridging", proxy_name_clone);
                                                let ws_conn =
                                                    WebSocketConn::new(ws_stream, visitor_addr);
                                                if let Err(e) = rust_frp_util::bridge_streams(
                                                    ws_conn, work_conn,
                                                )
                                                .await
                                                {
                                                    log::error!(
                                                        "WebSocket bridge error for proxy {}: {:?}",
                                                        proxy_name_clone,
                                                        e
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                log::error!(
                                                    "Failed to get work conn for {}: {}",
                                                    proxy_name_clone,
                                                    e
                                                );
                                            }
                                        }
                                    });
                                }
                                Err(e) => {
                                    log::error!("accept WebSocket connection error: {:?}", e);
                                    break;
                                }
                            }
                        }
                        log::info!("WebSocket proxy {} stopped", proxy_name);
                    });

                    let mut listeners = listeners.write().await;
                    listeners.insert(config.name.clone(), (listener_arc, running));
                    let mut handles = self.accept_handles.write().await;
                    handles.insert(config.name.clone(), handle);
                }
            }
            _ => {
                log::warn!("unsupported proxy type: {}", config.r#type);
            }
        }
        Ok(())
    }

    pub async fn stop_proxy(
        &self,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log::info!("Stopping proxy: {}", name);

        // 从 HTTP 虚拟主机路由器中注销
        self.http_vhost_router.unregister_proxy(name).await;

        // 负载均衡分组：成员退出组
        // - 组内仍有成员：保留共享监听器（故障摘除，流量由剩余成员承接）
        // - 组已空：关闭共享监听器（键为组端口，非代理名）
        let group_port = {
            let proxies = self.proxies.read().await;
            proxies
                .get(name)
                .and_then(|c| c.group.as_ref().and(c.remote_port))
        };
        if let Some(port) = group_port {
            let remaining = self.group_registry.member_count(port).await;
            let empty = self.group_registry.leave(port, name).await;
            if !empty {
                log::info!(
                    "proxy [{}] left group on port {} ({} remaining members, keeping shared listener)",
                    name,
                    port,
                    remaining.saturating_sub(1)
                );
                return Ok(());
            }
            let key = group_listener_key(port);
            let mut accept_handles = self.accept_handles.write().await;
            if let Some(handle) = accept_handles.remove(&key) {
                handle.abort();
                // 等待任务实际退出，确保监听 socket 释放后再返回
                //（否则新代理立刻重绑同端口会 AddrInUse）
                let _ = handle.await;
                log::info!("aborted group accept task for port {}", port);
            }
            let mut listeners = self.listeners.write().await;
            if let Some((_, running)) = listeners.remove(&key) {
                running.store(false, std::sync::atomic::Ordering::Relaxed);
            }
            log::info!("group on port {} is empty, stopped shared listener", port);
            return Ok(());
        }

        // 中止 accept 任务，立即释放端口
        let mut accept_handles = self.accept_handles.write().await;
        if let Some(handle) = accept_handles.remove(name) {
            handle.abort();
            // 等待任务实际退出，确保监听 socket 释放（防重绑 AddrInUse 竞态）
            let _ = handle.await;
            log::info!("aborted accept task for proxy: {}", name);
        }

        // 停止 TCP 监听器（清理残留状态）
        let mut listeners = self.listeners.write().await;
        if let Some((_, running)) = listeners.remove(name) {
            running.store(false, std::sync::atomic::Ordering::Relaxed);
            log::info!("stopped TCP proxy: {}", name);
        }

        // 停止 UDP 会话
        let mut udp_sessions = self.udp_sessions.write().await;
        if let Some(session) = udp_sessions.remove(name) {
            session
                .running
                .store(false, std::sync::atomic::Ordering::Relaxed);
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            log::info!("stopped UDP proxy: {}", name);
        }
        Ok(())
    }

    /// 释放代理占用的用户端口配额（幂等，未记录时为空操作）
    async fn release_user_quota(&self, proxy_name: &str) {
        let entry = self.proxy_user_ports.write().await.remove(proxy_name);
        if let Some((user, ports_used)) = entry {
            let mut counts = self.user_port_counts.write().await;
            if let Some(current) = counts.get_mut(&user) {
                *current = current.saturating_sub(ports_used);
                if *current == 0 {
                    counts.remove(&user);
                }
            }
        }
    }

    /// 添加代理的统一入口
    ///
    /// - `user: Some(user)` 时执行 max_ports_per_user 配额检查与记账
    /// - 启动失败时回滚 proxies map 与配额预占，修复失败后残留条目的问题
    async fn add_proxy_inner(
        &self,
        config: &rust_frp_config::ProxyConfig,
        user: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 1. 同名代理冲突检查（与 frp 行为一致，防止覆盖导致旧监听器泄漏）
        {
            let proxies = self.proxies.read().await;
            if proxies.contains_key(&config.name) {
                return Err(format!("proxy [{}] already exists", config.name).into());
            }
        }

        // 1.5 负载均衡分组校验：仅 TCP、与插件互斥、必须指定 remote_port
        if let Some(ref group) = config.group {
            if config.r#type != "tcp" {
                return Err(format!(
                    "proxy [{}] rejected: group is only supported for tcp proxies",
                    config.name
                )
                .into());
            }
            if config.plugin.is_some() {
                return Err(format!(
                    "proxy [{}] rejected: group and plugin cannot be used together",
                    config.name
                )
                .into());
            }
            if config.remote_port.is_none() {
                return Err(format!(
                    "proxy [{}] rejected: group [{}] requires remote_port",
                    config.name, group
                )
                .into());
            }
        }

        // 2. 用户端口配额检查与预占（TCP/UDP 各占 1 个端口，其他类型不占用，与 frp 一致）
        let ports_used: usize = match config.r#type.as_str() {
            "tcp" | "udp" => 1,
            _ => 0,
        };
        let quota_tracked = user.is_some() && ports_used > 0 && self.max_ports_per_user.is_some();
        if quota_tracked {
            let user = user.unwrap();
            let limit = self.max_ports_per_user.unwrap();
            let mut counts = self.user_port_counts.write().await;
            let current = counts.get(user).copied().unwrap_or(0);
            if current + ports_used > limit {
                return Err(format!(
                    "proxy [{}] rejected: user [{}] exceeds max_ports_per_user limit {}",
                    config.name, user, limit
                )
                .into());
            }
            counts.insert(user.to_string(), current + ports_used);
            drop(counts);
            self.proxy_user_ports
                .write()
                .await
                .insert(config.name.clone(), (user.to_string(), ports_used));
        }

        // 3. 先写入 map 声明代理名，启动失败则回滚
        {
            let mut proxies = self.proxies.write().await;
            proxies.insert(config.name.clone(), config.clone());
        }
        if let Err(e) = self.start_proxy(config).await {
            let mut proxies = self.proxies.write().await;
            proxies.remove(&config.name);
            if quota_tracked {
                self.release_user_quota(&config.name).await;
            }
            log::error!(
                "failed to start proxy [{}], rolled back: {:?}",
                config.name,
                e
            );
            return Err(e);
        }
        Ok(())
    }

    /// 发送 UDP 数据包到指定访问者
    pub async fn send_udp_packet(
        &self,
        proxy_name: &str,
        data: &[u8],
        client_addr: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let udp_sessions = self.udp_sessions.read().await;
        if let Some(session) = udp_sessions.get(proxy_name) {
            let addr: SocketAddr = client_addr.parse()?;
            session.socket.send_to(data, &addr).await?;
            Ok(())
        } else {
            Err(format!("UDP proxy session not found: {}", proxy_name).into())
        }
    }

    pub fn get_http_vhost_router(&self) -> Arc<HttpVhostRouter> {
        self.http_vhost_router.clone()
    }
}

#[async_trait::async_trait]
impl ProxyManager for ServerProxyManager {
    async fn add_proxy(
        &self,
        config: rust_frp_config::ProxyConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.add_proxy_inner(&config, None).await
    }

    async fn add_proxy_for_user(
        &self,
        config: rust_frp_config::ProxyConfig,
        user: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.add_proxy_inner(&config, Some(user)).await
    }

    async fn remove_proxy(
        &self,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.stop_proxy(name).await?;
        let mut proxies = self.proxies.write().await;
        proxies.remove(name);
        // 释放该代理占用的用户端口配额
        self.release_user_quota(name).await;
        Ok(())
    }

    async fn get_proxy_status(
        &self,
        name: &str,
    ) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
        let proxies = self.proxies.read().await;
        if proxies.contains_key(name) {
            Ok(Some("running".to_string()))
        } else {
            Ok(None)
        }
    }

    async fn clear(&self) {
        let mut proxies = self.proxies.write().await;
        proxies.clear();
        self.user_port_counts.write().await.clear();
        self.proxy_user_ports.write().await.clear();
        log::info!("Server proxy manager cleared");
    }

    async fn send_udp_packet(
        &self,
        proxy_name: &str,
        data: &[u8],
        client_addr: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let udp_sessions = self.udp_sessions.read().await;
        if let Some(session) = udp_sessions.get(proxy_name) {
            let addr: SocketAddr = client_addr.parse()?;
            session.socket.send_to(data, &addr).await?;
            Ok(())
        } else {
            Err(format!("UDP proxy session not found: {}", proxy_name).into())
        }
    }
}

/// 服务器访问者管理器
pub struct ServerVisitorManager {
    visitors: RwLock<std::collections::HashMap<String, rust_frp_config::VisitorConfig>>,
}

impl Default for ServerVisitorManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerVisitorManager {
    pub fn new() -> Self {
        Self {
            visitors: RwLock::new(std::collections::HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl VisitorManager for ServerVisitorManager {
    async fn add_visitor(
        &self,
        config: rust_frp_config::VisitorConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut visitors = self.visitors.write().await;
        visitors.insert(config.name.clone(), config);
        Ok(())
    }

    async fn remove_visitor(
        &self,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut visitors = self.visitors.write().await;
        visitors.remove(name);
        Ok(())
    }

    async fn clear(&self) {
        let mut visitors = self.visitors.write().await;
        visitors.clear();
        log::info!("Server visitor manager cleared");
    }
}

fn create_routes(
    server: std::sync::Arc<Server>,
    user: Option<String>,
    password: Option<String>,
) -> axum::Router {
    let app = axum::Router::new()
        .route("/health", axum::routing::get(health_handler))
        .route("/metrics", axum::routing::get(prometheus_handler))
        .route("/api/metrics", axum::routing::get(metrics_handler))
        .route("/api/controllers", axum::routing::get(controllers_handler))
        .route("/api/proxies", axum::routing::get(proxies_handler))
        .route("/", axum::routing::get(index_handler))
        .route("/index.html", axum::routing::get(index_handler))
        .route("/login", axum::routing::get(login_handler))
        .route("/login", axum::routing::post(login_post_handler))
        .route("/logout", axum::routing::get(logout_handler))
        .route("/api/reload", axum::routing::post(reload_handler))
        .with_state(server);

    if let (Some(ref user_val), Some(ref password_val)) = (&user, &password) {
        log::info!("Web server authentication enabled");
        let web_user = user_val.clone();
        let web_password = password_val.clone();

        std::thread::spawn(move || {
            std::env::set_var("FRP_WEB_USER", web_user);
            std::env::set_var("FRP_WEB_PASSWORD", web_password);
        });

        let auth_user = user_val.clone();
        let auth_password = password_val.clone();
        app.layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let user = auth_user.clone();
                let password = auth_password.clone();
                async move {
                    let path = request.uri().path();

                    if path == "/login" || path == "/metrics" {
                        return next.run(request).await;
                    }

                    let cookies = request.headers().get("cookie");
                    let session_valid = cookies
                        .and_then(|c| c.to_str().ok())
                        .and_then(|c| {
                            c.split(';')
                                .find(|s| s.trim().starts_with("frp_session="))
                                .map(|s| s.trim().split('=').nth(1).unwrap_or(""))
                        })
                        .and_then(|session| {
                            let decoded = base64::decode(session).ok()?;
                            let data = String::from_utf8(decoded).ok()?;
                            let parts: Vec<&str> = data.split(':').collect();
                            if parts.len() == 2 && parts[0] == user && parts[1] == password {
                                Some(true)
                            } else {
                                None
                            }
                        })
                        .is_some();

                    if session_valid {
                        next.run(request).await
                    } else {
                        axum::http::Response::builder()
                            .status(axum::http::StatusCode::SEE_OTHER)
                            .header("Location", "/login")
                            .body("Redirecting to login".to_string())
                            .unwrap()
                            .into_response()
                    }
                }
            },
        ))
    } else {
        log::info!("Web server authentication disabled");
        app
    }
}

async fn health_handler() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "ok",
        "timestamp": get_timestamp(),
    }))
}

async fn reload_handler(
    State(server): State<std::sync::Arc<Server>>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    if let Some(ref tx) = server.reload_tx {
        match tx.send(()).await {
            Ok(_) => (
                axum::http::StatusCode::OK,
                axum::Json(serde_json::json!({
                    "success": true,
                    "message": "Reload signal sent"
                })),
            ),
            Err(_) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({
                    "success": false,
                    "error": "Failed to send reload signal"
                })),
            ),
        }
    } else {
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "Hot reload not configured (config_path not set)"
            })),
        )
    }
}

async fn metrics_handler(
    State(server): State<std::sync::Arc<Server>>,
) -> axum::Json<serde_json::Value> {
    let metrics = server.metrics.get_metrics();
    axum::Json(metrics)
}

/// Prometheus text exposition format 端点（免认证，供 Prometheus 抓取）
async fn prometheus_handler() -> impl axum::response::IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        global_metrics().render_prometheus(),
    )
}

async fn controllers_handler(
    State(server): State<std::sync::Arc<Server>>,
) -> axum::Json<Vec<serde_json::Value>> {
    let clients = server.control_manager.get_clients().await;
    let controller_list: Vec<serde_json::Value> = clients
        .into_iter()
        .map(|client| {
            serde_json::json!({
                "user": client.user,
                "client_id": client.client_id,
                "run_id": client.run_id,
                "connected_at": client.connected_at.elapsed().as_secs(),
                "last_heartbeat": client.last_heartbeat.elapsed().as_secs(),
            })
        })
        .collect();
    axum::Json(controller_list)
}

async fn proxies_handler(
    State(server): State<std::sync::Arc<Server>>,
) -> axum::Json<Vec<serde_json::Value>> {
    let proxies = server.proxy_manager.proxies.read().await;
    let owners = server.proxy_manager.proxy_owners.read().await;
    let clients = server.control_manager.get_clients().await;
    let client_map: std::collections::HashMap<String, String> = clients
        .into_iter()
        .map(|c| (c.run_id, c.client_id))
        .collect();

    let proxy_list: Vec<serde_json::Value> = proxies
        .values()
        .map(|proxy| {
            let client_id = owners
                .get(&proxy.name)
                .and_then(|run_id| client_map.get(run_id))
                .cloned()
                .unwrap_or_else(|| "-".to_string());

            serde_json::json!({
                "name": proxy.name,
                "type": proxy.r#type,
                "local_ip": proxy.local_ip,
                "local_port": proxy.local_port,
                "remote_port": proxy.remote_port,
                "plugin": proxy.plugin,
                "client": client_id,
            })
        })
        .collect();
    axum::Json(proxy_list)
}

async fn index_handler() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("../web_ui.html"))
}

async fn login_handler() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("../login.html"))
}

async fn login_post_handler(body: String) -> impl axum::response::IntoResponse {
    let parts: Vec<(String, String)> = body
        .split('&')
        .filter_map(|s| {
            let mut parts = s.split('=');
            let key = parts.next()?.replace('+', " ");
            let value = parts.next()?.replace('+', " ");
            Some((
                key,
                urlencoding::decode(&value).unwrap_or_default().to_string(),
            ))
        })
        .collect();

    let username: String = parts
        .iter()
        .find(|(k, _)| k == "username")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let password: String = parts
        .iter()
        .find(|(k, _)| k == "password")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    use std::sync::OnceLock;
    static USER: OnceLock<String> = OnceLock::new();
    static PASSWORD: OnceLock<String> = OnceLock::new();

    let config_user =
        USER.get_or_init(|| std::env::var("FRP_WEB_USER").unwrap_or_else(|_| "admin".to_string()));
    let config_password = PASSWORD
        .get_or_init(|| std::env::var("FRP_WEB_PASSWORD").unwrap_or_else(|_| "admin".to_string()));

    if username == *config_user && password == *config_password {
        let session = base64::encode(format!("{}:{}", config_user, config_password));
        axum::http::Response::builder()
            .status(axum::http::StatusCode::SEE_OTHER)
            .header("Location", "/")
            .header(
                "Set-Cookie",
                format!("frp_session={}; HttpOnly; Path=/", session),
            )
            .body("Redirecting to dashboard".to_string())
            .unwrap()
    } else {
        axum::http::Response::builder()
            .status(axum::http::StatusCode::UNAUTHORIZED)
            .body("Unauthorized".to_string())
            .unwrap()
    }
}

async fn logout_handler() -> impl axum::response::IntoResponse {
    axum::http::Response::builder()
        .status(axum::http::StatusCode::SEE_OTHER)
        .header("Location", "/login")
        .header("Set-Cookie", "frp_session=; HttpOnly; Path=/; Max-Age=0")
        .body("Logged out".to_string())
        .unwrap()
}

/// Web 服务器（基于 axum）
pub struct WebServer {
    addr: SocketAddr,
    server: Option<tokio::task::JoinHandle<()>>,
    user: Option<String>,
    password: Option<String>,
}

impl WebServer {
    pub fn new(
        config: &rust_frp_config::WebServerConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let addr = format!("{}:{}", config.addr, config.port).parse::<SocketAddr>()?;
        Ok(Self {
            addr,
            server: None,
            user: config.user.clone(),
            password: config.password.clone(),
        })
    }

    pub async fn start(&mut self, server: &Server) -> Result<(), Box<dyn std::error::Error>> {
        let server = std::sync::Arc::new(server.clone());
        let user = self.user.clone();
        let password = self.password.clone();

        let app = create_routes(server, user, password);
        self.start_http(app).await?;
        Ok(())
    }

    async fn start_http(&mut self, app: axum::Router) -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind(self.addr).await?;
        log::info!("Web server listening on http://{}", self.addr);

        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        self.server = Some(handle);
        Ok(())
    }
}

/// HTTP 虚拟主机监听器
pub struct HttpVhostListener {
    inner: std::sync::Arc<tokio::net::TcpListener>,
}

impl HttpVhostListener {
    pub async fn bind(addr: &SocketAddr) -> Result<Self, std::io::Error> {
        let inner = tokio::net::TcpListener::bind(addr).await?;
        Ok(Self {
            inner: std::sync::Arc::new(inner),
        })
    }

    pub async fn accept(&self) -> Result<(tokio::net::TcpStream, SocketAddr), std::io::Error> {
        self.inner.accept().await
    }

    pub fn get_listener(&self) -> std::sync::Arc<tokio::net::TcpListener> {
        self.inner.clone()
    }
}

/// HTTPS 虚拟主机监听器
pub struct HttpsVhostListener {
    inner: std::sync::Arc<tokio::net::TcpListener>,
    tls_config: TlsConfig,
}

impl HttpsVhostListener {
    pub async fn bind(addr: &SocketAddr, tls_config: TlsConfig) -> Result<Self, std::io::Error> {
        let inner = tokio::net::TcpListener::bind(addr).await?;
        Ok(Self {
            inner: std::sync::Arc::new(inner),
            tls_config,
        })
    }

    pub async fn accept(
        &self,
    ) -> Result<
        (
            tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
            SocketAddr,
        ),
        std::io::Error,
    > {
        let (conn, addr) = self.inner.accept().await?;
        let tls_conn = self.tls_config.accept(conn).await?;
        Ok((tls_conn, addr))
    }

    pub fn get_listener(&self) -> std::sync::Arc<tokio::net::TcpListener> {
        self.inner.clone()
    }
}

/// 服务器服务
#[allow(dead_code)]
pub struct Server {
    config: ServerConfig,
    control_manager: Arc<ControlManager>,
    proxy_manager: Arc<ServerProxyManager>,
    visitor_manager: Arc<ServerVisitorManager>,
    auth_manager: Arc<AuthManager>,
    conn_manager: ConnManager,
    tcp_listener: Option<TcpListener>,
    udp_listener: Option<UdpListener>,
    vhost_http_listener: Option<HttpVhostListener>,
    vhost_https_listener: Option<HttpsVhostListener>,
    /// 工作连接监听器
    work_conn_listener: Option<tokio::net::TcpListener>,
    web_server: Option<WebServer>,
    metrics: Arc<MonitorMetrics>,
    /// 工作连接管理器
    work_conn_manager: Arc<ServerWorkConnManager>,
    /// 代理所有权映射 (proxy_name -> run_id)
    proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
    /// STCP 桥接管理器
    stcp_bridge_manager: Arc<StcpBridgeManager>,
    /// XTCP 访问者映射 (proxy_name -> visitor_run_id)
    xtcp_visitors: Arc<RwLock<std::collections::HashMap<String, String>>>,
    /// 配置文件路径（用于热重载）
    config_path: Option<String>,
    /// 重载信号接收器
    reload_rx: Option<tokio::sync::mpsc::Receiver<()>>,
    /// 重载信号发送器（供 WebServer API 使用）
    reload_tx: Option<tokio::sync::mpsc::Sender<()>>,
}

impl Server {
    pub async fn new(
        config: ServerConfig,
        config_path: Option<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let auth_manager = Arc::new(AuthManager::new(&config.auth).map_err(|e| e.to_string())?);
        let control_manager = Arc::new(ControlManager::new());
        let http_vhost_router = Arc::new(HttpVhostRouter::new());
        let work_conn_manager = Arc::new(ServerWorkConnManager::new(
            config.transport.pool_count as usize,
        ));
        let proxy_owners = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let proxy_manager = Arc::new(ServerProxyManager::new(
            http_vhost_router,
            proxy_owners.clone(),
            control_manager.clone(),
            work_conn_manager.clone(),
            auth_manager.clone(),
            config.allow_ports.clone(),
            config.max_ports_per_user,
        ));
        let visitor_manager = Arc::new(ServerVisitorManager::new());
        let metrics = Arc::new(MonitorMetrics::new());
        // 注册进程级单例，供 Control::run 等深层调用点使用
        set_global_metrics(metrics.clone());

        let tls_config = if let Some(tls) = &config.transport.tls {
            if tls.enable {
                if let (Some(cert_file), Some(key_file)) = (&tls.cert_file, &tls.key_file) {
                    Some(TlsConfig::new_server(cert_file, key_file)?)
                } else {
                    // 使用内置自签名证书
                    Some(TlsConfig::new_server_with_builtin_cert()?)
                }
            } else {
                None
            }
        } else {
            None
        };

        let conn_manager = ConnManager::new(tls_config, config.transport.pool_count as usize);
        let stcp_bridge_manager = Arc::new(StcpBridgeManager::new());
        let xtcp_visitors = Arc::new(RwLock::new(std::collections::HashMap::new()));

        // tls_only 前置校验：强制 TLS 必须先启用 TLS
        if config.transport.tls_only && conn_manager.get_tls_config().is_none() {
            return Err(
                "tls_only requires transport.tls.enable = true (with cert/key or builtin cert)"
                    .into(),
            );
        }

        let mut web_server = None;
        if config.web_server.port > 0 {
            web_server = Some(WebServer::new(&config.web_server)?);
        }

        Ok(Self {
            config,
            control_manager,
            proxy_manager,
            visitor_manager,
            auth_manager,
            conn_manager,
            tcp_listener: None,
            udp_listener: None,
            vhost_http_listener: None,
            vhost_https_listener: None,
            work_conn_listener: None,
            web_server,
            metrics,
            work_conn_manager,
            proxy_owners,
            stcp_bridge_manager,
            xtcp_visitors,
            config_path,
            reload_rx: None,
            reload_tx: None,
        })
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // 启动监控任务
        self.start_monitor_task().await;

        // 启动 Web 服务器
        if let Some(mut web_server) = self.web_server.take() {
            web_server.start(self).await?;
            log::info!("web server started");
            self.web_server = Some(web_server);
        }

        // 启动 TCP 监听器
        let addr =
            format!("{}:{}", self.config.bind_addr, self.config.bind_port).parse::<SocketAddr>()?;
        let tcp_listener = TcpListener::bind(&addr).await?;
        self.tcp_listener = Some(tcp_listener);
        log::info!("TCP listener started on {}", addr);

        // 启动 UDP 监听器（如果配置了 KCP 或 QUIC）
        if let Some(kcp_port) = self.config.kcp_bind_port {
            let addr = format!("{}:{}", self.config.bind_addr, kcp_port).parse::<SocketAddr>()?;
            let udp_listener = UdpListener::bind(&addr).await?;
            self.udp_listener = Some(udp_listener);
            log::info!("UDP listener started on {}", addr);
        }

        // 启动 HTTP 虚拟主机监听器
        let vhost_http_port = self.config.vhost_http_port.unwrap_or(9090);
        log::info!("HTTP vhost listener started on {}", vhost_http_port);

        let addr =
            format!("{}:{}", self.config.bind_addr, vhost_http_port).parse::<SocketAddr>()?;
        let vhost_listener = HttpVhostListener::bind(&addr).await?;
        self.vhost_http_listener = Some(vhost_listener);

        // 启动 HTTP 虚拟主机连接处理任务
        let http_vhost_router = self.proxy_manager.get_http_vhost_router();
        let vhost_listener = self.vhost_http_listener.as_ref().unwrap();
        let metrics = self.metrics.clone();
        self.start_http_vhost_handler(vhost_listener, http_vhost_router, metrics)
            .await?;

        // 启动 HTTPS 虚拟主机监听器
        let tls_config = self.conn_manager.get_tls_config();
        if let Some(tls_cfg) = tls_config {
            let vhost_https_port = self.config.vhost_https_port.unwrap_or(9091);
            log::info!("HTTPS vhost listener started on {}", vhost_https_port);
            let addr =
                format!("{}:{}", self.config.bind_addr, vhost_https_port).parse::<SocketAddr>()?;
            let vhost_listener = HttpsVhostListener::bind(&addr, tls_cfg.clone()).await?;
            self.vhost_https_listener = Some(vhost_listener);
            log::info!("HTTPS vhost listener started on {}", addr);

            // 启动 HTTPS 虚拟主机连接处理任务
            let http_vhost_router = self.proxy_manager.get_http_vhost_router();
            let vhost_listener = self.vhost_https_listener.as_ref().unwrap();
            let metrics = self.metrics.clone();
            self.start_https_vhost_handler(vhost_listener, http_vhost_router, metrics)
                .await?;
        } else {
            log::warn!("No TLS config available, HTTPS vhost disabled");
        }

        // 启动工作连接监听器（如果配置了 work_conn_port）
        let work_conn_port = self
            .config
            .work_conn_port
            .unwrap_or(self.config.bind_port + 1000);
        let work_conn_addr =
            format!("{}:{}", self.config.bind_addr, work_conn_port).parse::<SocketAddr>()?;
        let std_listener = std::net::TcpListener::bind(work_conn_addr)?;
        std_listener.set_nonblocking(true)?;
        let std_listener_clone = std_listener.try_clone()?;
        let work_conn_listener = tokio::net::TcpListener::from_std(std_listener)?;
        let work_conn_listener_clone = tokio::net::TcpListener::from_std(std_listener_clone)?;
        log::info!("Work connection listener started on {}", work_conn_addr);

        // 启动工作连接处理任务
        // TLS 协商：服务器启用 TLS 时工作连接监听器同步支持 TLS（嗅探 0x16 首字节），
        // tls_only 时拒绝一切明文工作连接
        let work_conn_tls_config = self.conn_manager.get_tls_config().cloned();
        let work_conn_tls_only = self.config.transport.tls_only;
        let control_manager = self.control_manager.clone();
        let work_conn_manager = self.work_conn_manager.clone();
        let auth_manager = self.auth_manager.clone();
        let stcp_bridge_manager_work = self.stcp_bridge_manager.clone();
        tokio::spawn(async move {
            Self::handle_work_connections(
                work_conn_listener_clone,
                control_manager,
                work_conn_manager,
                auth_manager,
                stcp_bridge_manager_work,
                work_conn_tls_config,
                work_conn_tls_only,
            )
            .await;
        });

        self.work_conn_listener = Some(work_conn_listener);

        // 开始处理连接
        log::info!("Starting connection handlers...");

        // 启动 KCP 连接处理器（如果启用了 KCP）
        // tls_only 下拒绝启动 KCP：KCP 为明文 UDP，无法满足强制 TLS 要求
        if let Some(ref _udp_listener) = self.udp_listener {
            if self.config.transport.tls_only {
                log::error!("tls_only is enabled, refusing to start KCP listener (plaintext UDP)");
                return Err("tls_only is enabled but KCP is plaintext UDP; disable kcp_bind_port or tls_only".into());
            }
            log::info!("KCP connection handler enabled");
            let control_manager = self.control_manager.clone();
            let proxy_manager = self.proxy_manager.clone();
            let visitor_manager = self.visitor_manager.clone();
            let auth_manager = self.auth_manager.clone();
            let proxy_owners = self.proxy_owners.clone();
            let metrics = self.metrics.clone();
            let work_conn_manager = self.work_conn_manager.clone();
            let stcp_bridge_manager = self.stcp_bridge_manager.clone();
            let xtcp_visitors = self.xtcp_visitors.clone();
            let kcp_work_conn_tls = self.conn_manager.get_tls_config().is_some();
            let kcp_listener = KcpListener::bind(
                format!(
                    "{}:{}",
                    self.config.bind_addr,
                    self.config
                        .kcp_bind_port
                        .unwrap_or(self.config.bind_port + 1)
                )
                .parse::<SocketAddr>()?,
            )
            .await?;

            tokio::spawn(async move {
                loop {
                    match kcp_listener.accept().await {
                        Ok((kcp_conn, addr)) => {
                            log::info!("new KCP connection from: {:?}", addr);
                            metrics.increment_connections();
                            let cm = control_manager.clone();
                            let pm = proxy_manager.clone();
                            let vm = visitor_manager.clone();
                            let am = auth_manager.clone();
                            let po = proxy_owners.clone();
                            let m = metrics.clone();
                            let wcm = work_conn_manager.clone();
                            let sbm = stcp_bridge_manager.clone();
                            let xv = xtcp_visitors.clone();

                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_kcp_connection(
                                    kcp_conn,
                                    cm,
                                    pm,
                                    vm,
                                    am,
                                    po,
                                    xv,
                                    wcm,
                                    sbm,
                                    kcp_work_conn_tls,
                                )
                                .await
                                {
                                    log::error!("handle KCP connection error: {:?}", e);
                                }
                                m.decrement_connections();
                            });
                        }
                        Err(e) => {
                            log::error!("Failed to accept KCP connection: {:?}", e);
                            break;
                        }
                    }
                }
            });
        }

        // 启动 TCP 连接处理器
        self.handle_tcp_connections().await?;
        Ok(())
    }

    /// 处理工作连接（支持 TLS/明文混跑 + tls_only 强制）
    async fn handle_work_connections(
        listener: tokio::net::TcpListener,
        control_manager: Arc<ControlManager>,
        work_conn_manager: Arc<ServerWorkConnManager>,
        auth_manager: Arc<AuthManager>,
        stcp_bridge_manager: Arc<StcpBridgeManager>,
        tls_config: Option<TlsConfig>,
        tls_only: bool,
    ) {
        log::info!(
            "Work connection handler started (tls: {}, tls_only: {})",
            tls_config.is_some(),
            tls_only
        );

        loop {
            match listener.accept().await {
                Ok((mut conn, addr)) => {
                    let cm = control_manager.clone();
                    let wcm = work_conn_manager.clone();
                    let am = auth_manager.clone();
                    let sbm = stcp_bridge_manager.clone();
                    let tls_config = tls_config.clone();

                    tokio::spawn(async move {
                        // 嗅探首字节：0x16 = TLS ClientHello，其余视为明文协议
                        let mut first_byte = [0u8; 1];
                        let n = match conn.peek(&mut first_byte).await {
                            Ok(n) => n,
                            Err(e) => {
                                log::debug!("Work conn peek failed from {:?}: {}", addr, e);
                                return;
                            }
                        };
                        if n == 0 {
                            log::debug!("Work conn from {:?} closed before sending data", addr);
                            return;
                        }

                        match classify_work_conn(first_byte[0], tls_config.is_some(), tls_only) {
                            WorkConnClass::Tls => {
                                let tls_config = match tls_config {
                                    Some(c) => c,
                                    None => unreachable!(),
                                };
                                log::info!("New TLS work connection from: {:?}", addr);
                                match tls_config.accept(conn).await {
                                    Ok(tls_stream) => {
                                        if let Err(e) = Self::process_work_conn(
                                            Box::new(tls_stream),
                                            cm,
                                            wcm,
                                            am,
                                            sbm,
                                        )
                                        .await
                                        {
                                            log_work_conn_error(&e);
                                        }
                                    }
                                    Err(e) => {
                                        global_metrics().incr_tls_rejects();
                                        log::warn!("TLS accept failed for work conn: {}", e);
                                    }
                                }
                            }
                            WorkConnClass::Plain => {
                                log::info!("New work connection from: {:?}", addr);
                                if let Err(e) =
                                    Self::process_work_conn(Box::new(conn), cm, wcm, am, sbm).await
                                {
                                    log_work_conn_error(&e);
                                }
                            }
                            WorkConnClass::Reject => {
                                global_metrics().incr_tls_rejects();
                                log::warn!(
                                    "Rejected work connection from {:?} (tls_only = {})",
                                    addr,
                                    tls_only
                                );
                                let _ = conn.shutdown().await;
                            }
                        }
                    });
                }
                Err(e) => {
                    log::error!("Failed to accept work connection: {:?}", e);
                    break;
                }
            }
        }

        log::info!("Work connection handler stopped");
    }

    /// 处理单个工作连接
    async fn process_work_conn(
        mut conn: AnyConn,
        control_manager: Arc<ControlManager>,
        work_conn_manager: Arc<ServerWorkConnManager>,
        auth_manager: Arc<AuthManager>,
        stcp_bridge_manager: Arc<StcpBridgeManager>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 读取客户端发送的 NewWorkConn 消息
        let msg = rust_frp_core::read_message(&mut conn).await?;

        match msg {
            Message::NewWorkConn(work_msg) => {
                log::info!(
                    "Work conn for proxy: {}, run_id: {}",
                    work_msg.proxy_name,
                    work_msg.run_id
                );

                // 验证 run_id 是否存在
                if control_manager.get_msg_tx(&work_msg.run_id).await.is_none() {
                    log::error!("Unknown run_id: {}", work_msg.run_id);
                    let resp = Message::StartWorkConn(rust_frp_core::StartWorkConnMsg {
                        error: "Unknown run_id".to_string(),
                        src_addr: String::new(),
                        src_port: 0,
                        dst_addr: String::new(),
                        dst_port: 0,
                    });
                    rust_frp_core::write_message(&mut conn, &resp).await?;
                    return Err("Unknown run_id".into());
                }

                // 验证 sign_key（如果服务器生成了 sign_key，客户端必须匹配）
                if !work_msg.sign_key.is_empty() {
                    match auth_manager
                        .generate_work_conn_sign_key(&work_msg.run_id)
                        .await
                    {
                        Ok(expected_key) => {
                            if work_msg.sign_key != expected_key {
                                log::error!("Sign key mismatch for proxy: {}", work_msg.proxy_name);
                                let resp =
                                    Message::StartWorkConn(rust_frp_core::StartWorkConnMsg {
                                        error: "Sign key verification failed".to_string(),
                                        src_addr: String::new(),
                                        src_port: 0,
                                        dst_addr: String::new(),
                                        dst_port: 0,
                                    });
                                rust_frp_core::write_message(&mut conn, &resp).await?;
                                return Err("Sign key mismatch".into());
                            }
                        }
                        Err(e) => {
                            log::error!("Failed to generate expected sign_key: {:?}", e);
                        }
                    }
                }

                // 不再立即发送 StartWorkConn，连接放入池中等待访客取用
                // 检查是否是 STCP 桥接工作连接（用 proxy_name 作为 bridge_id）
                match stcp_bridge_manager
                    .add_conn_and_try_bridge(&work_msg.proxy_name, conn)
                    .await
                {
                    Ok(Some((c1, c2))) => {
                        log::info!(
                            "STCP bridge both sides ready for {}, bridging",
                            work_msg.proxy_name
                        );
                        let proxy_name = work_msg.proxy_name.clone();
                        tokio::spawn(async move {
                            if let Err(e) = rust_frp_util::bridge_streams(c1, c2).await {
                                log::error!("STCP bridge error for {}: {:?}", proxy_name, e);
                            }
                        });
                        return Ok(());
                    }
                    Ok(None) => {
                        // 连接已存入 STCP 桥接，等待另一半
                        return Ok(());
                    }
                    Err(conn) => {
                        // 没有 STCP 桥接，放入工作连接池
                        work_conn_manager
                            .register_work_conn(&work_msg.proxy_name, conn)
                            .await;
                    }
                }
            }
            _ => {
                log::warn!("Unexpected message on work conn: {:?}", msg);
                return Err("Unexpected message on work conn".into());
            }
        }

        Ok(())
    }

    async fn start_http_vhost_handler(
        &self,
        listener: &HttpVhostListener,
        http_vhost_router: Arc<HttpVhostRouter>,
        metrics: Arc<MonitorMetrics>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener_arc = listener.get_listener();
        let proxy_owners = self.proxy_owners.clone();
        let control_manager = self.control_manager.clone();
        let work_conn_manager = self.work_conn_manager.clone();
        let auth_manager = self.auth_manager.clone();

        tokio::spawn(async move {
            loop {
                match listener_arc.accept().await {
                    Ok((conn, addr)) => {
                        log::info!("new HTTP vhost connection from: {:?}", addr);
                        metrics.increment_connections();
                        let router = http_vhost_router.clone();
                        let metrics_clone = metrics.clone();
                        let po = proxy_owners.clone();
                        let cm = control_manager.clone();
                        let wcm = work_conn_manager.clone();
                        let am = auth_manager.clone();

                        tokio::spawn(async move {
                            if let Err(e) =
                                Self::handle_http_vhost_connection(conn, router, po, cm, wcm, am)
                                    .await
                            {
                                if e.to_string().to_lowercase().contains("connection reset")
                                    || e.to_string().to_lowercase().contains("connection aborted")
                                    || e.to_string().to_lowercase().contains("broken pipe")
                                {
                                    log::debug!(
                                        "HTTP vhost connection closed (peer disconnected): {:?}",
                                        e
                                    );
                                } else {
                                    log::error!("handle http vhost connection error: {:?}", e);
                                }
                            }
                            metrics_clone.decrement_connections();
                        });
                    }
                    Err(e) => {
                        log::error!("accept HTTP vhost connection error: {:?}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    async fn start_https_vhost_handler(
        &self,
        listener: &HttpsVhostListener,
        http_vhost_router: Arc<HttpVhostRouter>,
        metrics: Arc<MonitorMetrics>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener_arc = listener.get_listener();
        let tls_config = listener.tls_config.clone();
        let proxy_owners = self.proxy_owners.clone();
        let control_manager = self.control_manager.clone();
        let work_conn_manager = self.work_conn_manager.clone();
        let auth_manager = self.auth_manager.clone();

        tokio::spawn(async move {
            loop {
                match listener_arc.accept().await {
                    Ok((conn, addr)) => {
                        log::info!("new HTTPS vhost connection from: {:?}", addr);
                        metrics.increment_connections();
                        let router = http_vhost_router.clone();
                        let tls_config = tls_config.clone();
                        let metrics_clone = metrics.clone();
                        let po = proxy_owners.clone();
                        let cm = control_manager.clone();
                        let wcm = work_conn_manager.clone();
                        let am = auth_manager.clone();

                        tokio::spawn(async move {
                            // 先进行 TLS 握手
                            match tls_config.accept(conn).await {
                                Ok(tls_conn) => {
                                    if let Err(e) = Self::handle_https_vhost_connection(
                                        tls_conn, router, po, cm, wcm, am, addr,
                                    )
                                    .await
                                    {
                                        if e.to_string().to_lowercase().contains("connection reset")
                                            || e.to_string()
                                                .to_lowercase()
                                                .contains("connection aborted")
                                            || e.to_string().to_lowercase().contains("broken pipe")
                                        {
                                            log::debug!("HTTPS vhost connection closed (peer disconnected): {:?}", e);
                                        } else {
                                            log::error!(
                                                "handle https vhost connection error: {:?}",
                                                e
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::error!("TLS handshake error: {:?}", e);
                                }
                            }
                            metrics_clone.decrement_connections();
                        });
                    }
                    Err(e) => {
                        log::error!("accept HTTPS vhost connection error: {:?}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    async fn handle_http_vhost_connection(
        mut conn: tokio::net::TcpStream,
        http_vhost_router: Arc<HttpVhostRouter>,
        proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
        control_manager: Arc<ControlManager>,
        work_conn_manager: Arc<ServerWorkConnManager>,
        _auth_manager: Arc<AuthManager>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 读取 HTTP 请求头
        let mut buf = [0u8; 4096];
        let n = conn.read(&mut buf).await?;

        if n == 0 {
            return Ok(());
        }

        // 解析 HTTP 请求
        let request_info = match HttpRequestInfo::parse(&buf[..n]) {
            Some(info) => info,
            None => {
                log::warn!("failed to parse HTTP request");
                let response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
                conn.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };

        log::info!(
            "HTTP request: {} {} Host: {}",
            request_info.method,
            request_info.path,
            request_info.host
        );

        // 根据 Host 查找代理
        let proxy_name = match http_vhost_router
            .find_proxy_by_host(&request_info.host)
            .await
        {
            Some(name) => name,
            None => {
                log::warn!("no proxy found for host: {}", request_info.host);
                let body = format!("Proxy not found for host: {}", request_info.host);
                let content_len = body.len();
                let response = format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                    content_len, body
                );
                conn.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };

        log::info!("routing HTTP request to proxy: {}", proxy_name);
        // per-proxy 连接统计守卫（drop 时自动减一）
        let _conn_guard = global_metrics()
            .get_proxy_stat(&proxy_name)
            .map(ProxyConnGuard::acquire);

        // 查找代理对应的 run_id
        let run_id = {
            let owners = proxy_owners.read().await;
            owners.get(&proxy_name).cloned()
        };

        let run_id = match run_id {
            Some(id) => id,
            None => {
                log::error!("No owner found for HTTP proxy: {}", proxy_name);
                let response = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 30\r\n\r\nProxy not registered by any client";
                conn.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };

        // 获取对应的消息通道
        let msg_tx = match control_manager.get_msg_tx(&run_id).await {
            Some(tx) => tx,
            None => {
                log::error!("Message channel not found for run_id: {}", run_id);
                let response = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 37\r\n\r\nMessage channel not found";
                conn.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };

        // 从池中获取工作连接
        let visitor_addr = conn
            .peer_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        match work_conn_manager
            .get_work_conn(&proxy_name, &msg_tx, Duration::from_secs(30), visitor_addr)
            .await
        {
            Ok(mut work_conn) => {
                log::info!("Got work conn for HTTP proxy {}, bridging", proxy_name);
                // 先发送已读取的 HTTP 数据到工作连接
                if n > 0 {
                    if let Err(e) = work_conn.write_all(&buf[..n]).await {
                        log::error!("Failed to write initial HTTP data to work conn: {:?}", e);
                        return Ok(());
                    }
                }
                // 桥接剩余数据
                if let Err(e) = rust_frp_util::bridge_streams(conn, work_conn).await {
                    log::error!("HTTP bridge error: {:?}", e);
                }
            }
            Err(e) => {
                log::error!(
                    "Failed to get work conn for HTTP proxy {}: {}",
                    proxy_name,
                    e
                );
                let response = "HTTP/1.1 504 Gateway Timeout\r\n\r\n";
                conn.write_all(response.as_bytes()).await?;
            }
        }

        Ok(())
    }

    async fn handle_https_vhost_connection<S>(
        mut conn: S,
        http_vhost_router: Arc<HttpVhostRouter>,
        proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
        control_manager: Arc<ControlManager>,
        work_conn_manager: Arc<ServerWorkConnManager>,
        _auth_manager: Arc<AuthManager>,
        visitor_addr: std::net::SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // 读取 HTTP 请求头（来自 TLS 解密后的数据）
        let mut buf = [0u8; 4096];
        let n = conn.read(&mut buf).await?;

        if n == 0 {
            return Ok(());
        }

        // 解析 HTTP 请求
        let request_info = match HttpRequestInfo::parse(&buf[..n]) {
            Some(info) => info,
            None => {
                log::warn!("failed to parse HTTPS request");
                let response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
                conn.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };

        log::info!(
            "HTTPS request: {} {} Host: {}",
            request_info.method,
            request_info.path,
            request_info.host
        );

        // 根据 Host 查找代理
        let proxy_name = match http_vhost_router
            .find_proxy_by_host(&request_info.host)
            .await
        {
            Some(name) => name,
            None => {
                log::warn!("no proxy found for host: {}", request_info.host);
                let body = format!("Proxy not found for host: {}", request_info.host);
                let content_len = body.len();
                let response = format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                    content_len, body
                );
                conn.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };

        log::info!("routing HTTPS request to proxy: {}", proxy_name);
        // per-proxy 连接统计守卫（drop 时自动减一）
        let _conn_guard = global_metrics()
            .get_proxy_stat(&proxy_name)
            .map(ProxyConnGuard::acquire);

        // 查找代理对应的 run_id
        let run_id = {
            let owners = proxy_owners.read().await;
            owners.get(&proxy_name).cloned()
        };

        let run_id = match run_id {
            Some(id) => id,
            None => {
                log::error!("No owner found for HTTPS proxy: {}", proxy_name);
                let response = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 30\r\n\r\nProxy not registered by any client";
                conn.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };

        // 获取对应的消息通道
        let msg_tx = match control_manager.get_msg_tx(&run_id).await {
            Some(tx) => tx,
            None => {
                log::error!("Message channel not found for run_id: {}", run_id);
                let response = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 37\r\n\r\nMessage channel not found";
                conn.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };

        // 从池中获取工作连接
        match work_conn_manager
            .get_work_conn(&proxy_name, &msg_tx, Duration::from_secs(30), visitor_addr)
            .await
        {
            Ok(work_conn) => {
                log::info!("Got work conn for HTTPS proxy {}, bridging", proxy_name);
                // 先发送已读取的 HTTP 数据到工作连接
                // 注意：对于 HTTPS，conn 是 TLS 流，work_conn 是普通 TCP
                // 我们先写已读数据，然后用 bridge_streams 桥接 TLS 流和 TCP 流
                let initial_data = buf[..n].to_vec();
                let mut work_conn_clone = work_conn;
                if !initial_data.is_empty() {
                    if let Err(e) = work_conn_clone.write_all(&initial_data).await {
                        log::error!("Failed to write initial HTTPS data to work conn: {:?}", e);
                        return Ok(());
                    }
                }
                // 使用 bridge_streams 桥接 TLS 流和 TCP 流
                if let Err(e) = rust_frp_util::bridge_streams(conn, work_conn_clone).await {
                    log::error!("HTTPS bridge error: {:?}", e);
                }
            }
            Err(e) => {
                log::error!(
                    "Failed to get work conn for HTTPS proxy {}: {}",
                    proxy_name,
                    e
                );
                let response = "HTTP/1.1 504 Gateway Timeout\r\n\r\n";
                conn.write_all(response.as_bytes()).await?;
            }
        }

        Ok(())
    }

    async fn start_monitor_task(&self) {
        let metrics = self.metrics.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let metrics_data = metrics.get_metrics();
                log::info!(
                    "Monitor: uptime={}s, connections={}/{}, proxies={}/{}, traffic={}KB/{}",
                    metrics_data["uptime"],
                    metrics_data["current_connections"],
                    metrics_data["total_connections"],
                    metrics_data["current_proxies"],
                    metrics_data["total_proxies"],
                    metrics_data["bytes_sent"].as_u64().unwrap() / 1024,
                    metrics_data["bytes_received"].as_u64().unwrap() / 1024
                );
            }
        });
    }

    async fn handle_tcp_connections(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(listener) = &self.tcp_listener {
            let tls_config = if let Some(ref tls) = self.config.transport.tls {
                if tls.enable {
                    if let (Some(ref cert_file), Some(ref key_file)) =
                        (&tls.cert_file, &tls.key_file)
                    {
                        Some(TlsConfig::new_server(cert_file, key_file)?)
                    } else {
                        Some(TlsConfig::new_server_with_builtin_cert()?)
                    }
                } else {
                    None
                }
            } else {
                None
            };

            let mut reload_rx = self.reload_rx.take();
            let config_path = self.config_path.clone();

            loop {
                if let Some(ref mut rx) = reload_rx {
                    tokio::select! {
                        result = listener.accept() => {
                            let (conn, addr) = match result {
                                Ok(v) => v,
                                Err(e) => {
                                    log::error!("accept error: {:?}", e);
                                    continue;
                                }
                            };
                            log::info!("new connection from: {:?}", addr);
                            self.metrics.increment_connections();
                            let control_manager = self.control_manager.clone();
                            let proxy_manager = self.proxy_manager.clone();
                            let visitor_manager = self.visitor_manager.clone();
                            let auth_manager = self.auth_manager.clone();
                            let proxy_owners = self.proxy_owners.clone();
                            let metrics = self.metrics.clone();
                            let tls_config = tls_config.clone();
                            let work_conn_manager = self.work_conn_manager.clone();
                            let stcp_bridge_manager = self.stcp_bridge_manager.clone();
                            let xtcp_visitors = self.xtcp_visitors.clone();

                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(
                                    conn,
                                    control_manager,
                                    proxy_manager,
                                    visitor_manager,
                                    auth_manager,
                                    proxy_owners,
                                    xtcp_visitors,
                                    tls_config,
                                    work_conn_manager,
                                    stcp_bridge_manager,
                                ).await {
                                    log::error!("handle connection error: {:?}", e);
                                }
                                metrics.decrement_connections();
                            });
                        }
                        _ = rx.recv() => {
                            log::info!("Reload signal received, reloading config...");
                            if let Err(e) = reload_server_config(&config_path, &mut self.config, &mut self.auth_manager).await {
                                log::error!("Reload config failed: {}", e);
                            }
                        }
                    }
                } else {
                    let (conn, addr) = listener.accept().await?;
                    log::info!("new connection from: {:?}", addr);
                    self.metrics.increment_connections();
                    let control_manager = self.control_manager.clone();
                    let proxy_manager = self.proxy_manager.clone();
                    let visitor_manager = self.visitor_manager.clone();
                    let auth_manager = self.auth_manager.clone();
                    let proxy_owners = self.proxy_owners.clone();
                    let metrics = self.metrics.clone();
                    let tls_config = tls_config.clone();
                    let work_conn_manager = self.work_conn_manager.clone();
                    let stcp_bridge_manager = self.stcp_bridge_manager.clone();
                    let xtcp_visitors = self.xtcp_visitors.clone();

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(
                            conn,
                            control_manager,
                            proxy_manager,
                            visitor_manager,
                            auth_manager,
                            proxy_owners,
                            xtcp_visitors,
                            tls_config,
                            work_conn_manager,
                            stcp_bridge_manager,
                        )
                        .await
                        {
                            log::error!("handle connection error: {:?}", e);
                        }
                        metrics.decrement_connections();
                    });
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        mut conn: tokio::net::TcpStream,
        control_manager: Arc<ControlManager>,
        proxy_manager: Arc<ServerProxyManager>,
        visitor_manager: Arc<ServerVisitorManager>,
        auth_manager: Arc<AuthManager>,
        proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
        xtcp_visitors: Arc<RwLock<std::collections::HashMap<String, String>>>,
        tls_config: Option<TlsConfig>,
        work_conn_manager: Arc<ServerWorkConnManager>,
        stcp_bridge_manager: Arc<StcpBridgeManager>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 首字节嗅探：TCP_MUX_MAGIC = tcp_mux 客户端（多路复用路径）
        let mut first = [0u8; 1];
        if conn.peek(&mut first).await.is_ok_and(|n| n == 1) && first[0] == TCP_MUX_MAGIC {
            // 消费 magic 字节（peek 不消费；不读掉会污染后续 TLS 握手）
            let mut b = [0u8; 1];
            conn.read_exact(&mut b).await?;
            log::info!("tcp_mux connection detected");
            return Self::handle_mux_connection(
                conn,
                control_manager,
                proxy_manager,
                visitor_manager,
                auth_manager,
                proxy_owners,
                xtcp_visitors,
                tls_config,
                work_conn_manager,
                stcp_bridge_manager,
            )
            .await;
        }

        // 工作连接 TLS 协商标志：与控制连接共用同一 TLS 配置
        let work_conn_tls = tls_config.is_some();
        let conn = if let Some(tls_config) = tls_config {
            // 处理 TLS 连接
            let tls_stream = match tls_config.accept(conn).await {
                Ok(s) => s,
                Err(e) => {
                    global_metrics().incr_tls_rejects();
                    log::warn!("TLS accept failed: {}", e);
                    return Err(format!("TLS accept failed: {}", e).into());
                }
            };
            ControlConn::new(Box::new(tls_stream))
        } else {
            // 处理普通 TCP 连接
            ControlConn::new(Box::new(conn))
        };

        Self::spawn_control(
            conn,
            control_manager,
            proxy_manager,
            visitor_manager,
            auth_manager,
            proxy_owners,
            xtcp_visitors,
            stcp_bridge_manager,
            work_conn_manager,
            work_conn_tls,
        );

        Ok(())
    }

    /// 启动控制连接处理任务（登录注册 + 控制循环 + 退出清理）
    ///
    /// 返回任务句柄：多路复用路径在控制流退出后据此关闭会话。
    #[allow(clippy::too_many_arguments)]
    fn spawn_control(
        conn: ControlConn,
        control_manager: Arc<ControlManager>,
        proxy_manager: Arc<ServerProxyManager>,
        visitor_manager: Arc<ServerVisitorManager>,
        auth_manager: Arc<AuthManager>,
        proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
        xtcp_visitors: Arc<RwLock<std::collections::HashMap<String, String>>>,
        stcp_bridge_manager: Arc<StcpBridgeManager>,
        work_conn_manager: Arc<ServerWorkConnManager>,
        work_conn_tls: bool,
    ) -> tokio::task::JoinHandle<()> {
        // 创建登录通知通道
        let (login_tx, mut login_rx) = mpsc::channel::<String>(1);

        // 创建消息发送通道（用于 Control::run 统一处理消息发送）
        let (msg_tx, msg_rx) = mpsc::channel::<Message>(100);

        // 创建控制器（不需要 Arc<Mutex>，因为只在一个任务中使用）
        let mut control = Control::new(
            conn,
            "".to_string(),
            "".to_string(),
            "".to_string(),
            proxy_manager,
            visitor_manager,
            auth_manager,
            control_manager.clone(),
            proxy_owners,
            xtcp_visitors,
            Some(login_tx),
            Some(msg_tx),
            stcp_bridge_manager,
            work_conn_manager,
            work_conn_tls,
        );

        let cm = control_manager.clone();

        // 克隆 msg_tx 用于注册
        let msg_tx_clone = control.msg_tx.clone();

        tokio::spawn(async move {
            // 启动控制循环
            let run_handle = tokio::spawn(async move {
                if let Err(e) = control.run(msg_rx).await {
                    log::error!("control run error: {:?}", e);
                }
            });

            // 等待登录成功，然后注册 msg_tx 到 ControlManager
            if let Some(run_id) = login_rx.recv().await {
                log::info!("Control registered for run_id: {}", run_id);
                // 注册消息通道
                if let Some(msg_tx) = msg_tx_clone {
                    cm.add(run_id.clone(), msg_tx).await.ok();
                }

                // 等待控制循环结束
                let _ = run_handle.await;

                // 清理：从 ControlManager 中移除
                cm.remove(&run_id).await.ok();
                log::info!("Control unregistered for run_id: {}", run_id);
            } else {
                // 登录失败或通道关闭
                let _ = run_handle.await;
            }
        })
    }

    /// 处理多路复用控制连接（tcp_mux 客户端）
    ///
    /// 连接结构：TLS（如启用）→ yamux 会话；首条流为控制流，
    /// 后续流为工作连接（与 work listener 共用 process_work_conn，协议零变更）。
    /// 控制流退出 → 关闭整个会话（分发循环随之结束）。
    #[allow(clippy::too_many_arguments)]
    async fn handle_mux_connection(
        conn: tokio::net::TcpStream,
        control_manager: Arc<ControlManager>,
        proxy_manager: Arc<ServerProxyManager>,
        visitor_manager: Arc<ServerVisitorManager>,
        auth_manager: Arc<AuthManager>,
        proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
        xtcp_visitors: Arc<RwLock<std::collections::HashMap<String, String>>>,
        tls_config: Option<TlsConfig>,
        work_conn_manager: Arc<ServerWorkConnManager>,
        stcp_bridge_manager: Arc<StcpBridgeManager>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 工作连接 TLS 协商标志（mux 下工作连接为会话流，TLS 在会话层；
        // 保持与 LoginResp 协商一致性）
        let work_conn_tls = tls_config.is_some();

        let io: AnyConn = if let Some(tls_config) = tls_config {
            let tls_stream = match tls_config.accept(conn).await {
                Ok(s) => s,
                Err(e) => {
                    global_metrics().incr_tls_rejects();
                    log::warn!("TLS accept failed (mux): {}", e);
                    return Err(format!("TLS accept failed: {}", e).into());
                }
            };
            Box::new(tls_stream)
        } else {
            Box::new(conn)
        };

        let session = MuxSession::new_server(io);

        // 首条流 = 控制流
        let control_stream = session.accept_stream().await?;
        // 分发循环所需的克隆（spawn_control 会移走原值）
        let am = auth_manager.clone();
        let sbm = stcp_bridge_manager.clone();
        let control_handle = Self::spawn_control(
            ControlConn::new(control_stream),
            control_manager.clone(),
            proxy_manager,
            visitor_manager,
            auth_manager,
            proxy_owners,
            xtcp_visitors,
            stcp_bridge_manager,
            work_conn_manager.clone(),
            work_conn_tls,
        );

        // 后续流 = 工作连接，逐条分发
        let dispatch_session = session.clone();
        let cm = control_manager.clone();
        let wcm = work_conn_manager.clone();
        let dispatch = tokio::spawn(async move {
            loop {
                match dispatch_session.accept_stream().await {
                    Ok(stream) => {
                        log::info!("New mux work stream");
                        let cm = cm.clone();
                        let wcm = wcm.clone();
                        let am = am.clone();
                        let sbm = sbm.clone();
                        tokio::spawn(async move {
                            if let Err(e) =
                                Server::process_work_conn(stream, cm, wcm, am, sbm).await
                            {
                                log_work_conn_error(&e);
                            }
                        });
                    }
                    Err(_) => break, // 会话关闭
                }
            }
            log::info!("Mux dispatch loop stopped");
        });

        // 控制流退出 → 关闭会话 → 分发循环退出
        let close_session = session.clone();
        tokio::spawn(async move {
            let _ = control_handle.await;
            log::info!("Mux control stream ended, closing session");
            close_session.close().await;
            let _ = dispatch.await;
        });

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_kcp_connection(
        kcp_conn: KcpConn,
        control_manager: Arc<ControlManager>,
        proxy_manager: Arc<ServerProxyManager>,
        visitor_manager: Arc<ServerVisitorManager>,
        auth_manager: Arc<AuthManager>,
        proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
        xtcp_visitors: Arc<RwLock<std::collections::HashMap<String, String>>>,
        work_conn_manager: Arc<ServerWorkConnManager>,
        stcp_bridge_manager: Arc<StcpBridgeManager>,
        work_conn_tls: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let conn = ControlConn::new(Box::new(kcp_conn));

        let (login_tx, mut login_rx) = mpsc::channel::<String>(1);
        let (msg_tx, msg_rx) = mpsc::channel::<Message>(100);

        let mut control = Control::new(
            conn,
            "".to_string(),
            "".to_string(),
            "".to_string(),
            proxy_manager,
            visitor_manager,
            auth_manager,
            control_manager.clone(),
            proxy_owners,
            xtcp_visitors,
            Some(login_tx),
            Some(msg_tx),
            stcp_bridge_manager.clone(),
            work_conn_manager.clone(),
            work_conn_tls,
        );

        let cm = control_manager.clone();
        let msg_tx_clone = control.msg_tx.clone();

        tokio::spawn(async move {
            let run_handle = tokio::spawn(async move {
                if let Err(e) = control.run(msg_rx).await {
                    log::error!("control run error: {:?}", e);
                }
            });

            if let Some(run_id) = login_rx.recv().await {
                log::info!("KCP Control registered for run_id: {}", run_id);
                if let Some(msg_tx) = msg_tx_clone {
                    cm.add(run_id.clone(), msg_tx).await.ok();
                }
                let _ = run_handle.await;
                cm.remove(&run_id).await.ok();
                log::info!("KCP Control unregistered for run_id: {}", run_id);
            } else {
                let _ = run_handle.await;
            }
        });

        Ok(())
    }

    /// 热重载配置
    ///
    /// 重新加载配置文件，应用新的配置项。
    /// 注意：不会重新绑定网络端口，仅更新代理/认证等运行时配置。
    pub async fn reload_config(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(config_path) = &self.config_path {
            log::info!("Reloading config from: {}", config_path);
            let new_config = rust_frp_config::ConfigLoader::load_server_config(config_path)?;

            self.config = new_config;
            self.auth_manager =
                Arc::new(AuthManager::new(&self.config.auth).map_err(|e| e.to_string())?);

            log::info!("Config reloaded successfully");
        }
        Ok(())
    }

    pub fn set_reload_rx(&mut self, rx: tokio::sync::mpsc::Receiver<()>) {
        self.reload_rx = Some(rx);
    }

    pub fn set_reload_tx(&mut self, tx: tokio::sync::mpsc::Sender<()>) {
        self.reload_tx = Some(tx);
    }
}

/// 从配置文件重载服务端配置（独立函数，避免 select! 中的借用冲突）
async fn reload_server_config(
    config_path: &Option<String>,
    config: &mut ServerConfig,
    auth_manager: &mut Arc<AuthManager>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(path) = config_path {
        log::info!("Reloading config from: {}", path);
        let new_config = rust_frp_config::ConfigLoader::load_server_config(path)?;

        *config = new_config;
        *auth_manager = Arc::new(AuthManager::new(&config.auth).map_err(|e| e.to_string())?);

        log::info!("Config reloaded successfully");
    }
    Ok(())
}

impl Clone for Server {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            control_manager: self.control_manager.clone(),
            proxy_manager: self.proxy_manager.clone(),
            visitor_manager: self.visitor_manager.clone(),
            auth_manager: self.auth_manager.clone(),
            conn_manager: ConnManager::new(None, self.config.transport.pool_count as usize),
            tcp_listener: None,
            udp_listener: None,
            vhost_http_listener: None,
            vhost_https_listener: None,
            work_conn_listener: None,
            web_server: None,
            metrics: self.metrics.clone(),
            work_conn_manager: self.work_conn_manager.clone(),
            proxy_owners: self.proxy_owners.clone(),
            stcp_bridge_manager: self.stcp_bridge_manager.clone(),
            xtcp_visitors: self.xtcp_visitors.clone(),
            config_path: self.config_path.clone(),
            reload_rx: None,
            reload_tx: self.reload_tx.clone(),
        }
    }
}
