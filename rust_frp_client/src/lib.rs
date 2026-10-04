//! FRP 客户端模块
//!
//! 该模块实现了 FRP 客户端（frpc）的核心功能。
//!
//! ## 客户端架构
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         Client                                  │
//! │  (主客户端结构，管理所有子组件)                                   │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!         ┌────────────────────┼────────────────────┐
//!         ▼                    ▼                    ▼
//! ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
//! │ ClientControl │   │ClientProxyMgr  │   │ClientVisitorMgr│
//! │ (控制连接)     │   │ (代理管理)     │   │ (访问者管理)   │
//! └───────────────┘   └───────────────┘   └───────────────┘
//!         │                    │                    │
//!         ▼                    ▼                    ▼
//! ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
//! │ WorkConnMgr   │   │  Connector    │   │  Connector    │
//! │ (工作连接管理) │   │ (网络连接)     │   │               │
//! └───────────────┘   └───────────────┘   └───────────────┘
//! ```
//!
//! ## 核心流程
//!
//! ### 1. 启动流程
//! ```text
//! Client::start()
//!   ├── 启动 Web 服务器（可选）
//!   ├── login() - 登录到服务器
//!   │     ├── 建立 TCP/TLS 连接
//!   │     ├── 发送 LoginMsg
//!   │     └── 接收 LoginRespMsg
//!   ├── 注册所有代理 (register_proxy)
//!   │     └── 发送 RegisterProxyMsg
//!   ├── 启动所有代理 (add_proxy)
//!   │     └── 创建工作连接处理器
//!   └── 运行控制循环 (run)
//!         ├── 处理服务器消息
//!         └── 监听信号退出
//! ```
//!
//! ### 2. 工作连接流程
//! ```text
//! 服务器                          客户端                          本地服务
//!   │                               │                              │
//!   │--- ReqWorkConnMsg ----------->│                              │
//!   │                               │                              │
//!   │                        establish_work_connection()            │
//!   │                               │                              │
//!   │                        连接工作端口 (server_port + 1000)       │
//!   │                               │                              │
//!   │<---- NewWorkConnMsg ----------│                              │
//!   │--- StartWorkConnMsg --------->│                              │
//!   │                               │ TcpStream::connect(local) -->│
//!   │                               │ 可选: PROXY header --------->│
//!   │<------ bridge_streams ------->│<---- bridge_streams -------->│
//! ```
//!
//! ## 安全性
//!
//! - TLS 加密连接（默认启用）
//! - HMAC 签名验证
//! - Token 认证
//! - 连接重试机制
//! - PROXY Protocol 支持（可选，透传真实访问者 IP）
//!
//! ## 配置示例
//!
//! ```toml
//! server_addr = "127.0.0.1"
//! server_port = 9300
//!
//! [[proxies]]
//! name = "ssh"
//! type = "tcp"
//! local_ip = "127.0.0.1"
//! local_port = 22
//! remote_port = 6000
//! ```

pub mod admin_client;

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rust_frp_auth::AuthManager;
use rust_frp_config::ClientConfig;
use rust_frp_core::{ControlConn, Message, NewWorkConnMsg, ProxyManager, VisitorManager};
use rust_frp_net::{ConnManager, KcpStream, MuxSession, TlsConfig, TCP_MUX_MAGIC};
use rust_frp_util::{
    get_timestamp, rand_id,
    retry::{retry, ConnectionError, RetryConfig},
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex, RwLock};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("no work conn handler for proxy: {0}")]
    NoWorkConnHandler(String),
    #[error("WorkConnManager not set")]
    WorkConnManagerNotSet,
    #[error("{0}")]
    Other(String),
}

type WorkConnSenderMap =
    RwLock<std::collections::HashMap<String, mpsc::Sender<(tokio::net::TcpStream, Vec<u8>)>>>;

/// 工作连接管理器
pub struct WorkConnManager {
    // proxy_name -> sender for incoming connections (with initial data)
    work_conn_senders: WorkConnSenderMap,
}

impl Default for WorkConnManager {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkConnManager {
    pub fn new() -> Self {
        Self {
            work_conn_senders: RwLock::new(std::collections::HashMap::new()),
        }
    }

    pub async fn register_work_conn_handler(
        &self,
        proxy_name: String,
        sender: mpsc::Sender<(tokio::net::TcpStream, Vec<u8>)>,
    ) {
        let mut senders = self.work_conn_senders.write().await;
        senders.insert(proxy_name, sender);
    }

    pub async fn get_work_conn_sender(
        &self,
        proxy_name: &str,
    ) -> Option<mpsc::Sender<(tokio::net::TcpStream, Vec<u8>)>> {
        let senders = self.work_conn_senders.read().await;
        senders.get(proxy_name).cloned()
    }

    pub async fn handle_work_conn(
        &self,
        proxy_name: &str,
        server_conn: tokio::net::TcpStream,
        initial_data: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(sender) = self.get_work_conn_sender(proxy_name).await {
            sender.send((server_conn, initial_data)).await?;
            Ok(())
        } else {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("No work conn handler for proxy: {}", proxy_name),
            )))
        }
    }
}

/// 客户端代理管理器
pub struct ClientProxyManager {
    proxies: RwLock<std::collections::HashMap<String, rust_frp_config::ProxyConfig>>,
    listeners: RwLock<std::collections::HashMap<String, std::sync::Arc<tokio::net::TcpListener>>>,
    work_conn_handlers: RwLock<std::collections::HashMap<String, tokio::task::JoinHandle<()>>>,
    work_conn_manager: Option<Arc<WorkConnManager>>,
    /// 传输层全局带宽限制（transport.bandwidth_limit），作为代理级配置的回落值
    default_bandwidth_limit: Option<String>,
    /// per-proxy 累计流量（键为代理名）
    traffic: RwLock<std::collections::HashMap<String, Arc<ProxyTraffic>>>,
}

/// per-proxy 累计流量计数器（客户端视角）
#[derive(Default)]
pub struct ProxyTraffic {
    /// 服务端 → 本地服务（下行）
    pub bytes_down: std::sync::atomic::AtomicU64,
    /// 本地服务 → 服务端（上行）
    pub bytes_up: std::sync::atomic::AtomicU64,
}

impl ProxyTraffic {
    /// 累加一次转发（桥接结束后调用）
    pub fn add(&self, down: u64, up: u64) {
        use std::sync::atomic::Ordering;
        self.bytes_down.fetch_add(down, Ordering::Relaxed);
        self.bytes_up.fetch_add(up, Ordering::Relaxed);
    }

    /// 读取快照 (down, up)
    pub fn snapshot(&self) -> (u64, u64) {
        use std::sync::atomic::Ordering;
        (
            self.bytes_down.load(Ordering::Relaxed),
            self.bytes_up.load(Ordering::Relaxed),
        )
    }
}

impl Default for ClientProxyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientProxyManager {
    pub fn new() -> Self {
        Self {
            proxies: RwLock::new(std::collections::HashMap::new()),
            listeners: RwLock::new(std::collections::HashMap::new()),
            work_conn_handlers: RwLock::new(std::collections::HashMap::new()),
            work_conn_manager: None,
            default_bandwidth_limit: None,
            traffic: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// 取（或创建）某代理的流量计数器
    async fn traffic_counter(&self, proxy_name: &str) -> Arc<ProxyTraffic> {
        {
            let map = self.traffic.read().await;
            if let Some(c) = map.get(proxy_name) {
                return c.clone();
            }
        }
        let mut map = self.traffic.write().await;
        map.entry(proxy_name.to_string())
            .or_insert_with(|| Arc::new(ProxyTraffic::default()))
            .clone()
    }

    /// 记录一次转发流量（工作连接处理热路径调用）
    pub async fn record_traffic(&self, proxy_name: &str, down: u64, up: u64) {
        self.traffic_counter(proxy_name).await.add(down, up);
    }

    /// 读取某代理的流量快照 (down, up)，无记录时返回 None
    pub async fn traffic_snapshot(&self, proxy_name: &str) -> Option<(u64, u64)> {
        let map = self.traffic.read().await;
        map.get(proxy_name).map(|c| c.snapshot())
    }

    pub fn set_work_conn_manager(&mut self, work_conn_manager: Arc<WorkConnManager>) {
        self.work_conn_manager = Some(work_conn_manager);
    }

    /// 设置传输层全局带宽限制，作为代理级未配置时的回落值
    pub fn set_default_bandwidth_limit(&mut self, bandwidth_limit: Option<String>) {
        self.default_bandwidth_limit = bandwidth_limit;
    }

    /// 启动工作连接处理器
    pub async fn start_work_conn_handler(
        &self,
        proxy_name: String,
        local_addr: SocketAddr,
        mut receiver: mpsc::Receiver<(tokio::net::TcpStream, Vec<u8>)>,
        bandwidth_limit: Option<String>,
    ) {
        let proxy_name_clone = proxy_name.clone();
        // 预取流量计数器（Arc），供转发任务在桥接结束后累加
        let traffic = self.traffic_counter(&proxy_name).await;
        // 限速配置为空表示不限速；非法值给出明确告警，而不是静默失效
        let rate_bytes_per_sec = match bandwidth_limit.as_deref() {
            Some(spec) => match rust_frp_util::parse_bandwidth_limit(spec) {
                Some(rate) => Some(rate),
                None => {
                    log::warn!(
                        "invalid bandwidth_limit \"{}\" for proxy {}; rate limiting disabled",
                        spec,
                        proxy_name_clone
                    );
                    None
                }
            },
            None => None,
        };

        let handle = tokio::spawn(async move {
            log::info!(
                "Starting work connection handler for proxy: {}",
                proxy_name_clone
            );

            while let Some((mut server_conn, initial_data)) = receiver.recv().await {
                log::info!("Received work connection for proxy: {}", proxy_name_clone);

                let retry_config = RetryConfig::fast();
                let connect_result = retry(
                    &retry_config,
                    &format!("connect to local service for proxy {}", proxy_name_clone),
                    || async {
                        tokio::net::TcpStream::connect(&local_addr)
                            .await
                            .map_err(|e| {
                                log::warn!("Connection attempt failed: {:?}", e);
                                ConnectionError::from(e)
                            })
                    },
                )
                .await;

                match connect_result {
                    Ok(retry_result) => {
                        let mut local_conn = retry_result.value;
                        log::info!(
                            "Connected to local service at {:?} for proxy: {} (attempts: {}, delay: {:?})",
                            local_addr,
                            proxy_name_clone,
                            retry_result.attempts,
                            retry_result.total_delay
                        );

                        // 首先发送已读取的初始数据
                        if !initial_data.is_empty() {
                            if let Err(e) = local_conn.write_all(&initial_data).await {
                                log::error!("Failed to write initial data to local conn: {:?}", e);
                                continue;
                            }
                        }

                        // 双向转发数据
                        if let Some(rate) = rate_bytes_per_sec {
                            let (server_read, server_write) = server_conn.split();
                            let (mut local_read, mut local_write) = local_conn.split();

                            let mut rate_limited_server_read =
                                rust_frp_util::RateLimitedReader::new(server_read, rate);
                            let mut rate_limited_server_write =
                                rust_frp_util::RateLimitedWriter::new(server_write, rate);

                            let server_to_local = async {
                                match tokio::io::copy(
                                    &mut rate_limited_server_read,
                                    &mut local_write,
                                )
                                .await
                                {
                                    Ok(n) => {
                                        log::info!(
                                            "Server to local: {} bytes transferred (rate: {}B/s)",
                                            n,
                                            rate
                                        );
                                        n
                                    }
                                    Err(e) => {
                                        log::error!("Server to local error: {:?}", e);
                                        0
                                    }
                                }
                            };

                            let local_to_server = async {
                                match tokio::io::copy(
                                    &mut local_read,
                                    &mut rate_limited_server_write,
                                )
                                .await
                                {
                                    Ok(n) => {
                                        log::info!(
                                            "Local to server: {} bytes transferred (rate: {}B/s)",
                                            n,
                                            rate
                                        );
                                        n
                                    }
                                    Err(e) => {
                                        log::error!("Local to server error: {:?}", e);
                                        0
                                    }
                                }
                            };

                            // 下行 = 服务端→本地，上行 = 本地→服务端
                            let (down, up) =
                                futures_util::future::join(server_to_local, local_to_server).await;
                            traffic.add(down, up);
                        } else {
                            match rust_frp_util::bridge_streams_counted(server_conn, local_conn)
                                .await
                            {
                                Ok((down, up)) => {
                                    log::info!(
                                        "Bidirectional bridge completed for proxy: {}",
                                        proxy_name_clone
                                    );
                                    traffic.add(down, up);
                                }
                                Err(e) => log::error!(
                                    "Bridge error for proxy {}: {:?}",
                                    proxy_name_clone,
                                    e
                                ),
                            }
                        }

                        log::info!("Work connection closed for proxy: {}", proxy_name_clone);
                    }
                    Err(e) => {
                        log::error!(
                            "Failed to connect to local service at {:?} after retries: {:?}",
                            local_addr,
                            e
                        );
                        // 发送 HTTP 错误响应
                        let error_response = format!(
                            "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\nFailed to connect to local service after retries: {}",
                            e.to_string().len() + 45,
                            e
                        );
                        let _ = server_conn.write_all(error_response.as_bytes()).await;
                    }
                }
            }

            log::info!(
                "Work connection handler stopped for proxy: {}",
                proxy_name_clone
            );
        });

        let mut handlers = self.work_conn_handlers.write().await;
        handlers.insert(proxy_name, handle);
    }

    pub async fn start_proxy(
        &self,
        config: &rust_frp_config::ProxyConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match config.r#type.as_str() {
            // tcpmux 与 tcp 同构：客户端不绑定端口，服务器在 tcpmux 复用端口
            // 上按域名路由后为每个 CONNECT 申请一条工作连接
            "tcp" | "http" | "https" | "websocket" | "tcpmux" => {
                let local_addr =
                    format!("{}:{}", config.local_ip, config.local_port).parse::<SocketAddr>()?;
                log::info!(
                    "starting {} proxy: {} -> {}",
                    config.r#type,
                    config.name,
                    local_addr
                );

                // 为 TCP 代理创建工作连接通道
                // 当服务器收到外部连接时，会通过这个通道通知客户端
                let (tx, rx) = mpsc::channel::<(tokio::net::TcpStream, Vec<u8>)>(100);
                // 代理级带宽限制优先；未配置时回落到传输层全局限制
                let bandwidth_limit = config
                    .bandwidth_limit
                    .clone()
                    .or_else(|| self.default_bandwidth_limit.clone());
                self.start_work_conn_handler(config.name.clone(), local_addr, rx, bandwidth_limit)
                    .await;

                // 注册工作连接发送器到 WorkConnManager
                if let Some(work_conn_manager) = &self.work_conn_manager {
                    work_conn_manager
                        .register_work_conn_handler(config.name.clone(), tx)
                        .await;
                } else {
                    log::error!("WorkConnManager not set for proxy: {}", config.name);
                    return Err("WorkConnManager not set".into());
                }

                Ok(())
            }
            _ => {
                log::warn!("unsupported proxy type: {}", config.r#type);
                Ok(())
            }
        }
    }

    pub async fn stop_proxy(
        &self,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut listeners = self.listeners.write().await;
        if let Some(listener) = listeners.remove(name) {
            // TcpListener doesn't have a shutdown method, we'll just drop it
            drop(listener);
        }

        // 停止工作连接处理器
        let mut handlers = self.work_conn_handlers.write().await;
        if let Some(handle) = handlers.remove(name) {
            handle.abort();
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl ProxyManager for ClientProxyManager {
    async fn add_proxy(
        &self,
        config: rust_frp_config::ProxyConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut proxies = self.proxies.write().await;
        proxies.insert(config.name.clone(), config.clone());
        drop(proxies);
        let _ = self.start_proxy(&config).await?;
        Ok(())
    }

    async fn remove_proxy(
        &self,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.stop_proxy(name).await?;
        let mut proxies = self.proxies.write().await;
        proxies.remove(name);
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

    async fn send_udp_packet(
        &self,
        _proxy_name: &str,
        _data: &[u8],
        _client_addr: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    async fn clear(&self) {
        // 停止所有工作连接处理器
        let handlers = self.work_conn_handlers.write().await;
        for (_, handle) in handlers.iter() {
            handle.abort();
        }
        drop(handlers);

        // 清空所有映射
        let mut proxies = self.proxies.write().await;
        proxies.clear();
        let mut listeners = self.listeners.write().await;
        listeners.clear();
        let mut work_conn_handlers = self.work_conn_handlers.write().await;
        work_conn_handlers.clear();

        log::info!("Proxy manager cleared");
    }
}

/// 客户端访问者管理器
pub struct ClientVisitorManager {
    visitors: RwLock<std::collections::HashMap<String, rust_frp_config::VisitorConfig>>,
}

impl Default for ClientVisitorManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientVisitorManager {
    pub fn new() -> Self {
        Self {
            visitors: RwLock::new(std::collections::HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl VisitorManager for ClientVisitorManager {
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
        log::info!("Visitor manager cleared");
    }
}

/// 构建客户端 TLS 配置（供控制连接与工作连接复用）
///
/// - 配置了 `trusted_ca_file` → 用该 CA 验证服务器证书（推荐）
/// - `trusted_ca_file` 未配置且 `skip_verify = true` → 跳过证书验证（仅加密，不认证）
/// - `trusted_ca_file` 未配置且 `skip_verify = false`（默认）→ **报错拒绝启动**（fail-closed），
///   避免在用户不知情时静默退化为"只加密不认证"
///
/// # ⚠️ 安全提示
///
/// `skip_verify = true` 意味着任何中间人都可以冒充服务端，仅应在测试环境使用。
/// 生产环境请务必配置 `transport.tls.trusted_ca_file`，并在服务端换用自建证书。
fn build_client_tls_config(
    config: &rust_frp_config::ClientConfig,
) -> Result<Option<TlsConfig>, Box<dyn std::error::Error>> {
    let Some(tls) = &config.transport.tls else {
        return Ok(None);
    };
    if !tls.enable {
        return Ok(None);
    }
    if let Some(ref ca_file) = tls.trusted_ca_file {
        return Ok(Some(TlsConfig::new_client_with_ca_file(ca_file)?));
    }
    if tls.skip_verify {
        log::warn!(
            "TLS enabled with transport.tls.skip_verify = true: the server certificate \
             will NOT be verified. This provides encryption only, NOT authentication."
        );
        return Ok(Some(TlsConfig::new_client_insecure()?));
    }
    Err(
        "TLS is enabled but transport.tls.trusted_ca_file is not set and \
         transport.tls.skip_verify is false: refusing to connect with unverified server \
         certificate (fail-closed). Set trusted_ca_file to pin the server CA, or set \
         skip_verify = true to explicitly accept the risk (encryption only, no authentication)."
            .into(),
    )
}

/// 计算服务器工作连接端口（frps.toml 的 work_conn_port，默认 server_port + 1000）
fn work_conn_port_of(config: &rust_frp_config::ClientConfig) -> u16 {
    config.work_conn_port.unwrap_or(config.server_port + 1000)
}

/// 客户端连接器
pub struct Connector {
    config: Arc<rust_frp_config::ClientConfig>,
    conn_manager: ConnManager,
}

impl Connector {
    pub fn new(
        config: Arc<rust_frp_config::ClientConfig>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let tls_config = build_client_tls_config(&config)?;

        let conn_manager = ConnManager::new(tls_config, config.transport.pool_count as usize);

        Ok(Self {
            config,
            conn_manager,
        })
    }

    pub async fn connect(
        &mut self,
    ) -> Result<rust_frp_net::PooledConn, Box<dyn std::error::Error>> {
        let addr = format!("{}:{}", self.config.server_addr, self.config.server_port)
            .parse::<SocketAddr>()?;
        Ok(self.conn_manager.connect_tcp(&addr).await?)
    }

    pub async fn connect_tls(
        &mut self,
        domain: &str,
    ) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, Box<dyn std::error::Error>>
    {
        let addr = format!("{}:{}", self.config.server_addr, self.config.server_port)
            .parse::<SocketAddr>()?;
        Ok(self.conn_manager.connect_tls(domain, &addr).await?)
    }

    pub async fn connect_kcp(
        &mut self,
    ) -> Result<rust_frp_net::KcpConn, Box<dyn std::error::Error>> {
        let addr = format!("{}:{}", self.config.server_addr, self.config.server_port)
            .parse::<SocketAddr>()?;
        Ok(self.conn_manager.connect_kcp(&addr).await?)
    }

    pub async fn connect_websocket(
        &mut self,
        url: &str,
    ) -> Result<
        rust_frp_net::WebSocketConn<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        Box<dyn std::error::Error>,
    > {
        Ok(self.conn_manager.connect_websocket(url).await?)
    }
}

/// XTCP 打洞会话注册表
///
/// visitor 侧每个等待打洞的本地连接注册一个 oneshot 通道；
/// 当 owner 回传的 `XtcpNatInfo` 经服务器中继到达时，按 proxy_name
/// 唤醒等待中的连接任务，携带 owner 的公网/本地地址。
///
/// 单槽语义：协议按 proxy_name 路由 NatInfo（无连接级 ID），
/// 同 proxy 同时只允许一个打洞会话；新会话注册时替换旧的，
/// 旧等待者 oneshot 关闭后自动回退 STCP 中继。
#[derive(Default)]
struct XtcpRegistry {
    /// proxy_name -> 等待 owner 地址的 oneshot
    pending: std::sync::Mutex<
        std::collections::HashMap<String, tokio::sync::oneshot::Sender<(String, String)>>,
    >,
}

impl XtcpRegistry {
    /// 注册一个等待 owner 地址的 visitor 会话，返回接收端。
    /// 同 proxy 已有等待者时替换之（旧接收端收到 RecvError → STCP 回退）。
    fn register(&self, proxy_name: String) -> tokio::sync::oneshot::Receiver<(String, String)> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(proxy_name, tx);
        rx
    }

    /// owner 地址到达时唤醒等待者；返回是否有等待者
    fn resolve(&self, proxy_name: &str, addrs: (String, String)) -> bool {
        if let Some(tx) = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(proxy_name)
        {
            let _ = tx.send(addrs);
            true
        } else {
            false
        }
    }
}

/// 客户端控制
// 部分通道字段（udp_resp_rx 等）由消息循环按需消费，整结构保留以便协议扩展
#[allow(dead_code)]
pub struct ClientControl {
    pub conn: ControlConn,
    run_id: String,
    proxy_manager: Arc<ClientProxyManager>,
    visitor_manager: Arc<ClientVisitorManager>,
    auth_manager: Arc<AuthManager>,
    work_conn_manager: Arc<WorkConnManager>,
    config: Arc<ClientConfig>,
    udp_sockets: RwLock<std::collections::HashMap<String, Arc<tokio::net::UdpSocket>>>,
    udp_resp_tx: tokio::sync::mpsc::Sender<Message>,
    udp_resp_rx: tokio::sync::mpsc::Receiver<Message>,
    stcp_visitor_tx: tokio::sync::mpsc::Sender<Message>,
    stcp_visitor_rx: tokio::sync::mpsc::Receiver<Message>,
    last_pong_time: std::time::Instant,
    /// 服务端通过 HTTP 插件拒绝了心跳（Pong 带 error），需要重连
    plugin_rejected_heartbeat: bool,
    /// 工作连接是否使用 TLS（来自服务器 LoginRespMsg.work_conn_tls 协商）
    work_conn_tls: bool,
    /// yamux 多路复用会话（tcp_mux 开启时存在）
    ///
    /// 工作连接不再新建 TCP，而是从会话打开新流；
    /// TLS 在会话层（底层 TCP 已含），流上无需重复加密。
    mux_session: Option<Arc<MuxSession>>,
    /// XTCP 打洞会话注册表（visitor 等待 owner NAT 信息）
    xtcp_registry: Arc<XtcpRegistry>,
}

/// 登录成功后构造控制会话所需的依赖集合（收敛 9 个独立参数，避免参数顺序误用）
pub struct ClientControlDeps {
    pub conn: ControlConn,
    pub run_id: String,
    pub proxy_manager: Arc<ClientProxyManager>,
    pub visitor_manager: Arc<ClientVisitorManager>,
    pub auth_manager: Arc<AuthManager>,
    pub work_conn_manager: Arc<WorkConnManager>,
    pub config: Arc<ClientConfig>,
    pub work_conn_tls: bool,
    pub mux_session: Option<Arc<MuxSession>>,
}

impl ClientControl {
    pub fn new(deps: ClientControlDeps) -> Self {
        let ClientControlDeps {
            conn,
            run_id,
            proxy_manager,
            visitor_manager,
            auth_manager,
            work_conn_manager,
            config,
            work_conn_tls,
            mux_session,
        } = deps;
        let (tx, rx) = tokio::sync::mpsc::channel::<Message>(256);
        let (stcp_tx, stcp_rx) = tokio::sync::mpsc::channel::<Message>(100);
        Self {
            conn,
            run_id,
            proxy_manager,
            visitor_manager,
            auth_manager,
            work_conn_manager,
            config,
            udp_sockets: RwLock::new(std::collections::HashMap::new()),
            udp_resp_tx: tx,
            udp_resp_rx: rx,
            stcp_visitor_tx: stcp_tx,
            stcp_visitor_rx: stcp_rx,
            last_pong_time: std::time::Instant::now(),
            plugin_rejected_heartbeat: false,
            work_conn_tls,
            mux_session,
            xtcp_registry: Arc::new(XtcpRegistry::default()),
        }
    }

    pub fn stcp_visitor_sender(&self) -> tokio::sync::mpsc::Sender<Message> {
        self.stcp_visitor_tx.clone()
    }

    /// XTCP 打洞会话注册表
    fn xtcp_registry(&self) -> Arc<XtcpRegistry> {
        self.xtcp_registry.clone()
    }

    /// 工作连接是否需要 TLS（服务器 LoginRespMsg.work_conn_tls 协商结果）
    pub fn work_conn_tls(&self) -> bool {
        self.work_conn_tls
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut msg_count = 0u32;
        // 心跳 10 秒一次（配合 Nginx proxy_read_timeout 300s 绰绰有余；
        // 断线时最多 20 秒就能发现：10s 没收到 pong → 触发下一次 ping → 发现写失败）
        let heartbeat_interval_secs: u64 = 10;
        let mut last_ping_time = std::time::Instant::now();

        log::debug!("ClientControl::run started, waiting for messages...");

        loop {
            // 定期发送 ping 消息
            if last_ping_time.elapsed() > std::time::Duration::from_secs(heartbeat_interval_secs) {
                let ping_msg = rust_frp_core::PingMsg {
                    timestamp: get_timestamp(),
                };
                log::debug!("Sending ping message, count: {}", msg_count);
                if let Err(e) = self.conn.write_message(&Message::Ping(ping_msg)).await {
                    log::error!("Failed to send ping (connection lost): {:?}", e);
                    break;
                }
                last_ping_time = std::time::Instant::now();
            }

            log::debug!("Waiting for message, count: {}", msg_count);

            tokio::select! {
                msg_result = tokio::time::timeout(std::time::Duration::from_secs(15), self.conn.read_message()) => {
                    match msg_result {
                        Ok(Ok(msg)) => {
                            msg_count += 1;
                            log::debug!("成功读取消息, 计数: {}", msg_count);
                            self.handle_message(msg).await;
                            if self.plugin_rejected_heartbeat {
                                log::warn!(
                                    "Server rejected heartbeat via plugin, reconnecting..."
                                );
                                break;
                            }
                        }
                        Ok(Err(e)) => {
                            log::error!("Failed to read message from connection: {:?}", e);
                            break;
                        }
                        Err(_elapsed) => {
                            if self.last_pong_time.elapsed() > std::time::Duration::from_secs(90) {
                                log::warn!(
                                    "Heartbeat timeout (no pong for {:?}), connection dead, reconnecting...",
                                    self.last_pong_time.elapsed()
                                );
                                break;
                            }
                        }
                    }
                }
                udp_msg = self.udp_resp_rx.recv() => {
                    if let Some(msg) = udp_msg {
                        log::debug!("Sending UDP response to server");
                        if let Err(e) = self.conn.write_message(&msg).await {
                            log::error!("Failed to send UDP response: {:?}", e);
                        }
                    }
                }
                msg = self.stcp_visitor_rx.recv() => {
                    if let Some(msg) = msg {
                        log::debug!("Sending STCP visitor message to server");
                        if let Err(e) = self.conn.write_message(&msg).await {
                            log::error!("Failed to send STCP visitor message: {:?}", e);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// 处理消息的通用方法
    async fn handle_message(&mut self, msg: Message) {
        match msg {
            Message::Pong(pong_msg) => {
                self.last_pong_time = std::time::Instant::now();
                if !pong_msg.error.is_empty() {
                    // 服务端 HTTP 插件拒绝了本次心跳：本会话不再被认可，触发重连
                    log::error!(
                        "Server rejected heartbeat via plugin: {}; reconnecting",
                        pong_msg.error
                    );
                    self.plugin_rejected_heartbeat = true;
                }
                log::debug!("收到 Pong 消息: timestamp={}", pong_msg.timestamp);
            }
            Message::ReqWorkConn(req_work_conn_msg) => {
                // 服务器请求建立工作连接
                log::debug!(
                    "收到 ReqWorkConn 消息: proxy={}",
                    req_work_conn_msg.proxy_name
                );
                log::info!(
                    "Received ReqWorkConn for proxy: {}",
                    req_work_conn_msg.proxy_name
                );
                let proxy_name = req_work_conn_msg.proxy_name.clone();
                let run_id = self.run_id.clone();
                let config = Arc::clone(&self.config);
                let work_conn_tls = self.work_conn_tls;
                let mux_session = self.mux_session.clone();

                tokio::spawn(async move {
                    log::debug!("开始建立工作连接: proxy={}", proxy_name);
                    if let Err(e) = establish_work_connection(
                        &proxy_name,
                        &run_id,
                        &config,
                        work_conn_tls,
                        mux_session.as_ref(),
                    )
                    .await
                    {
                        if e.to_string().to_lowercase().contains("connection reset")
                            || e.to_string().to_lowercase().contains("connection aborted")
                            || e.to_string().to_lowercase().contains("broken pipe")
                        {
                            log::debug!(
                                "Work connection for {} closed (peer disconnected): {:?}",
                                proxy_name,
                                e
                            );
                        } else {
                            log::error!(
                                "Failed to establish work connection for {}: {:?}",
                                proxy_name,
                                e
                            );
                        }
                    } else {
                        log::debug!("工作连接建立成功: proxy={}", proxy_name);
                    }
                });
            }
            Message::UdpPacket(udp_msg) => {
                let proxy_name = udp_msg.proxy_name;
                let data = udp_msg.data;
                let client_addr = udp_msg.client_addr.clone();

                let proxy_config = self
                    .config
                    .proxies
                    .iter()
                    .find(|p| p.name == proxy_name)
                    .cloned();

                if let Some(cfg) = proxy_config {
                    let local_addr = format!("{}:{}", cfg.local_ip, cfg.local_port);

                    let socket = {
                        let mut sockets = self.udp_sockets.write().await;
                        if let Some(s) = sockets.get(&proxy_name) {
                            s.clone()
                        } else {
                            match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                                Ok(s) => {
                                    let s = Arc::new(s);
                                    sockets.insert(proxy_name.clone(), s.clone());
                                    s
                                }
                                Err(e) => {
                                    log::error!(
                                        "Failed to bind UDP socket for proxy {}: {:?}",
                                        proxy_name,
                                        e
                                    );
                                    return;
                                }
                            }
                        }
                    };

                    if let Err(e) = socket.send_to(&data, &local_addr).await {
                        log::error!(
                            "Failed to send UDP data to {} for proxy {}: {:?}",
                            local_addr,
                            proxy_name,
                            e
                        );
                        return;
                    }

                    let resp_tx = self.udp_resp_tx.clone();
                    let proxy_name_clone = proxy_name.clone();
                    let client_addr_clone = client_addr.clone();
                    let socket_clone = socket.clone();
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 65535];
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            socket_clone.recv_from(&mut buf),
                        )
                        .await
                        {
                            Ok(Ok((n, _))) => {
                                let resp_data = buf[..n].to_vec();
                                let resp_msg = Message::UdpPacket(rust_frp_core::UdpPacketMsg {
                                    proxy_name: proxy_name_clone,
                                    data: resp_data,
                                    client_addr: client_addr_clone,
                                });
                                if let Err(e) = resp_tx.send(resp_msg).await {
                                    log::error!("Failed to send UDP response via channel: {:?}", e);
                                }
                            }
                            Ok(Err(e)) => {
                                log::error!(
                                    "UDP recv error for proxy {}: {:?}",
                                    proxy_name_clone,
                                    e
                                );
                            }
                            Err(_) => {
                                log::debug!("UDP response timeout for proxy {}", proxy_name_clone);
                            }
                        }
                    });
                } else {
                    log::error!("UDP proxy config not found: {}", proxy_name);
                }
            }
            Message::XtcpNatInfo(xtcp_msg) => {
                let proxy_name = xtcp_msg.proxy_name.clone();
                log::info!(
                    "Received XTCP NAT info from {} for proxy {}",
                    xtcp_msg.run_id,
                    proxy_name
                );

                // 本客户端提供该 proxy → owner 侧：回送自己的 NAT info 并启动 KCP 打洞
                if let Some(proxy_cfg) = self
                    .config
                    .proxies
                    .iter()
                    .find(|p| p.name == proxy_name)
                    .cloned()
                {
                    let tx = self.stcp_visitor_tx.clone();
                    let rid = self.run_id.clone();
                    let visitor_public = xtcp_msg.public_addr.clone();
                    let visitor_local = xtcp_msg.local_addr.clone();
                    tokio::spawn(async move {
                        run_xtcp_owner(proxy_cfg, visitor_public, visitor_local, tx, rid).await;
                    });
                } else {
                    // visitor 侧：owner 回传的 NAT info，唤醒等待打洞的连接任务
                    let resolved = self.xtcp_registry.resolve(
                        &proxy_name,
                        (xtcp_msg.public_addr.clone(), xtcp_msg.local_addr.clone()),
                    );
                    if !resolved {
                        log::debug!(
                            "XTCP NAT info for {} but no pending visitor session",
                            proxy_name
                        );
                    }
                }
            }
            Message::XtcpHolePunch(_) => {
                // KCP 打洞模式下不再使用 TCP HolePunch 消息（打洞包由 KcpStream 内置处理）
                log::debug!("ignoring legacy XtcpHolePunch message (KCP punch mode)");
            }
            _ => {
                log::warn!("unexpected message: {:?}", msg);
            }
        }
    }
}

/// 生成工作连接签名密钥（与服务端 AuthManager::generate_work_conn_sign_key 一致）
/// 解析登录所用的认证令牌
///
/// - `auth.method = "token"`：返回配置中的静态 token（缺省为空串）
/// - `auth.method = "oidc"`：向 IdP 的令牌端点以 `client_credentials` 换取
///   `access_token`；每次登录/重连都重新获取，避免复用已过期的令牌
async fn resolve_auth_token(
    config: &ClientConfig,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    if config.auth.method != "oidc" {
        return Ok(config.auth.token.clone().unwrap_or_default());
    }
    let oidc = config.auth.oidc.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "auth.oidc is required when auth.method = \"oidc\"",
        )
    })?;
    let token = rust_frp_auth::OidcClientCredentials::new(oidc)
        .fetch_access_token()
        .await
        .map_err(|e| format!("failed to obtain OIDC access token: {e}"))?;
    log::info!(
        "Obtained OIDC access token for login (expires_in={}s)",
        token.expires_in
    );
    Ok(token.access_token)
}

fn generate_work_conn_sign_key(token: &str, run_id: &str) -> String {
    use ring::{digest, hmac};
    // encryption_key = SHA-256(token)
    let mut hasher = digest::Context::new(&digest::SHA256);
    hasher.update(token.as_bytes());
    let encryption_key = hasher.finish();

    // sign_key = HMAC-SHA256(encryption_key, "work_conn:{run_id}")
    let msg = format!("work_conn:{}", run_id);
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, encryption_key.as_ref());
    let tag = hmac::sign(&hmac_key, msg.as_bytes());
    base64::encode(tag.as_ref())
}

/// 派生应用层加密密钥（SHA-256(token)，与服务端 AuthManager::generate_encryption_key 一致）
fn derive_encryption_key(token: &str) -> Vec<u8> {
    use ring::digest;
    let mut hasher = digest::Context::new(&digest::SHA256);
    hasher.update(token.as_bytes());
    hasher.finish().as_ref().to_vec()
}

/// 工作连接建立参数（收敛参数列表，避免长参数签名）
struct WorkConnRequest<'a> {
    proxy_name: &'a str,
    run_id: &'a str,
    work_conn_tls: bool,
    /// `Some` 时经 tcp_mux 会话流建立（协议与直连工作端口一致）
    mux_session: Option<&'a Arc<MuxSession>>,
    use_encryption: bool,
    use_compression: bool,
}

/// 打开工作连接并完成握手后的结果
///
/// 元组为 `(连接, 服务器观测到的访问者 IP, 访问者端口)`；后两项供
/// PROXY protocol v1 头使用。
type OpenedWorkConn = (Box<dyn rust_frp_net::FrpConn>, String, u16);

/// 打开一条到服务端的工作连接并完成 `NewWorkConn`/`StartWorkConn` 握手
///
/// 返回的连接在需要时已按固定顺序包装：**先压缩（内层）、后加密（外层）**，
/// 与服务器 [`rust_frp_server`] 及对端客户端保持一致。直连与 tcp_mux 两条
/// 路径共用本函数（握手消息明文，包装在握手之后）。
async fn open_work_conn(
    config: &ClientConfig,
    req: WorkConnRequest<'_>,
) -> Result<OpenedWorkConn, Box<dyn std::error::Error + Send + Sync>> {
    let WorkConnRequest {
        proxy_name,
        run_id,
        work_conn_tls,
        mux_session,
        use_encryption,
        use_compression,
    } = req;

    let mut work_conn: Box<dyn rust_frp_net::FrpConn> = if let Some(session) = mux_session {
        // tcp_mux：工作连接 = 会话流（服务端分发循环经 process_work_conn 处理，
        // 协议与直连工作端口完全一致）
        let stream = session
            .open_stream()
            .await
            .map_err(|e| format!("mux open work stream failed: {}", e))?;
        log::info!("Mux work stream established for proxy: {}", proxy_name);
        stream
    } else {
        // 直连工作端口路径
        let work_addr = format!("{}:{}", config.server_addr, work_conn_port_of(config));
        let tcp_conn = tokio::net::TcpStream::connect(&work_addr).await?;
        log::info!(
            "Connected to server work conn port: {} (proxy {})",
            work_addr,
            proxy_name
        );

        // 服务器协商要求 TLS 时，工作连接套 TLS（复用控制连接的客户端 TLS 配置）
        if work_conn_tls {
            let tls_config = build_client_tls_config(config)
                .map_err(|e| format!("failed to build client TLS config: {}", e))?
                .ok_or("server requires TLS work conn but client tls is disabled")?;
            let tls_stream = tls_config
                .connect(&config.server_addr, tcp_conn)
                .await
                .map_err(|e| format!("work conn TLS handshake failed: {}", e))?;
            log::info!("Work conn TLS established for proxy: {}", proxy_name);
            Box::new(tls_stream)
        } else {
            Box::new(tcp_conn)
        }
    };

    // 生成 sign_key
    let sign_key = config
        .auth
        .token
        .as_ref()
        .map(|token| generate_work_conn_sign_key(token, run_id))
        .unwrap_or_default();

    // 发送 NewWorkConn 消息
    let new_work_conn_msg = NewWorkConnMsg {
        run_id: run_id.to_string(),
        proxy_name: proxy_name.to_string(),
        timestamp: get_timestamp(),
        sign_key,
        use_encryption,
        use_compression,
    };
    rust_frp_core::write_message(&mut work_conn, &Message::NewWorkConn(new_work_conn_msg)).await?;

    // 等待 StartWorkConn 响应
    let (src_addr, src_port) = match rust_frp_core::read_message(&mut work_conn).await? {
        Message::StartWorkConn(start_msg) => {
            if !start_msg.error.is_empty() {
                return Err(format!("Server error: {}", start_msg.error).into());
            }
            log::info!("Work conn established for proxy: {}", proxy_name);
            (start_msg.src_addr, start_msg.src_port)
        }
        _ => {
            return Err("Unexpected response from server".into());
        }
    };

    // 应用层压缩与加密：握手完成后按固定顺序包装 —— 先压缩（内层）、后加密（外层）
    if use_compression {
        work_conn = Box::new(rust_frp_net::compress::CompressedStream::new(work_conn));
        log::info!(
            "Work conn application-layer compression (snappy) enabled for proxy: {}",
            proxy_name
        );
    }
    if use_encryption {
        let token = config
            .auth
            .token
            .as_deref()
            .ok_or("use_encryption requires a configured token")?;
        let key = derive_encryption_key(token);
        work_conn = Box::new(rust_frp_net::crypto::EncryptedStream::new(work_conn, &key)?);
        log::info!(
            "Work conn application-layer encryption (AES-256-GCM) enabled for proxy: {}",
            proxy_name
        );
    }

    Ok((work_conn, src_addr, src_port))
}

/// 建立工作连接（独立函数，供 ClientControl::run 调用）
///
/// - 多路复用：tcp_mux 会话存在时直接打开会话流（无需新建 TCP，TLS 在会话层）
/// - 端口：优先使用客户端配置的 work_conn_port，默认 server_port + 1000
/// - TLS：服务器通过 LoginRespMsg.work_conn_tls 协商后按需 TLS 加密
async fn establish_work_connection(
    proxy_name: &str,
    run_id: &str,
    config: &ClientConfig,
    work_conn_tls: bool,
    mux_session: Option<&Arc<MuxSession>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 查找代理配置
    let proxy_config = config
        .proxies
        .iter()
        .find(|p| p.name == proxy_name)
        .ok_or_else(|| format!("Proxy config not found: {}", proxy_name))?;

    // 应用层加密（fail-closed）：启用 use_encryption 必须已配置 token 以派生密钥
    let use_encryption = proxy_config.use_encryption;
    let use_compression = proxy_config.use_compression;
    if use_encryption && config.auth.token.is_none() {
        return Err(format!(
            "proxy [{}] enables use_encryption but client has no token configured",
            proxy_name
        )
        .into());
    }

    let (work_conn, src_addr, src_port) = open_work_conn(
        config,
        WorkConnRequest {
            proxy_name,
            run_id,
            work_conn_tls,
            mux_session,
            use_encryption,
            use_compression,
        },
    )
    .await?;

    // sudp 代理：工作连接上承载 UDP 包帧（不连接本地 TCP 服务）
    if proxy_config.r#type == "sudp" {
        let local_addr = format!("{}:{}", proxy_config.local_ip, proxy_config.local_port);
        return serve_sudp_proxy(work_conn, proxy_name, local_addr).await;
    }

    // 连接到本地服务
    let local_addr = format!("{}:{}", proxy_config.local_ip, proxy_config.local_port);
    let mut local_conn = tokio::net::TcpStream::connect(&local_addr).await?;
    log::info!("Connected to local service: {}", local_addr);

    // 如果启用了 PROXY protocol，先写入 header 再桥接
    let proxy_protocol_enabled = proxy_config.proxy_protocol.unwrap_or(false);
    if proxy_protocol_enabled && src_port > 0 {
        let header = format!(
            "PROXY TCP4 {} {} {} {}\r\n",
            src_addr, proxy_config.local_ip, src_port, proxy_config.local_port,
        );
        log::info!(
            "Writing PROXY protocol header for {}: {}",
            proxy_name,
            header.trim()
        );
        tokio::io::AsyncWriteExt::write_all(&mut local_conn, header.as_bytes()).await?;
    }

    // 双向桥接工作连接和本地连接
    rust_frp_util::bridge_streams(work_conn, local_conn).await?;
    Ok(())
}

// ============ XTCP P2P 打洞（STUN + UDP hole punching + KCP 通道） ============

/// STUN 探测公网端点；失败返回 None（上层回退/留空，由服务器观察地址兜底）
async fn stun_discover(socket: &Arc<tokio::net::UdpSocket>) -> Option<SocketAddr> {
    let servers = rust_frp_net::default_stun_socket_addrs().await;
    if servers.is_empty() {
        log::warn!("STUN: no servers resolved (DNS failed?)");
        return None;
    }
    match rust_frp_net::discover_public_endpoint(socket.clone(), &servers).await {
        Ok(addr) => {
            log::info!("STUN discovered public endpoint: {}", addr);
            Some(addr)
        }
        Err(e) => {
            log::warn!("STUN discovery failed: {}", e);
            None
        }
    }
}

/// 本机局域网 IPv4（UDP connect 技巧，只设置默认目标不实际发包）
async fn detect_local_ip() -> Option<std::net::Ipv4Addr> {
    let s = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    s.connect("8.8.8.8:80").await.ok()?;
    match s.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) => Some(v4),
        _ => None,
    }
}

/// 打洞 socket 的本地端点字符串（局域网 IP + 端口），同 NAT 下直连用
async fn local_endpoint_of(socket: &tokio::net::UdpSocket) -> String {
    let port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
    match detect_local_ip().await {
        Some(ip) => format!("{}:{}", ip, port),
        None => String::new(),
    }
}

/// 解析对端候选地址（公网优先，本地其次），去重、忽略空串
fn parse_peer_addrs(public: &str, local: &str) -> Vec<SocketAddr> {
    let mut peers = Vec::new();
    for s in [public, local] {
        if !s.is_empty() {
            if let Ok(a) = s.parse::<SocketAddr>() {
                if !peers.contains(&a) {
                    peers.push(a);
                }
            }
        }
    }
    peers
}

/// 等待 KCP 会话激活（收到对端有效输入 = 打洞成功）
async fn wait_kcp_active(stream: &KcpStream, timeout: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if stream.has_activity() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    stream.has_activity()
}

/// XTCP owner（proxy 提供方）打洞流程：
///
/// 1. 绑定 UDP socket（与 STUN 探测复用，保证 NAT 映射一致）
/// 2. STUN 探测公网地址，回送 `XtcpNatInfo` 给 visitor
/// 3. `KcpStream::accept` 等待 visitor 打洞（punch 包双向打通 NAT）
/// 4. 成功后连接本地被代理服务并桥接；超时/失败静默返回，
///    visitor 侧会回退 STCP 服务器中继
async fn run_xtcp_owner(
    proxy: rust_frp_config::ProxyConfig,
    visitor_public: String,
    visitor_local: String,
    msg_tx: tokio::sync::mpsc::Sender<Message>,
    run_id: String,
) {
    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            log::error!("XTCP owner bind UDP failed: {}", e);
            return;
        }
    };
    let public = stun_discover(&socket).await;
    let local_addr = local_endpoint_of(&socket).await;

    // 回送自己的 NAT info（owner 侧无需 secret_key 签名，服务端仅校验 visitor 侧）
    let nat_info = rust_frp_core::XtcpNatInfoMsg {
        proxy_name: proxy.name.clone(),
        run_id,
        nat_type: "unknown".to_string(),
        local_addr: local_addr.clone(),
        public_addr: public.as_ref().map(|a| a.to_string()).unwrap_or_default(),
        sign_key: String::new(),
        timestamp: 0,
    };
    if let Err(e) = msg_tx.send(Message::XtcpNatInfo(nat_info)).await {
        log::error!("XTCP owner failed to send NAT info: {}", e);
        return;
    }

    let peers = parse_peer_addrs(&visitor_public, &visitor_local);
    if peers.is_empty() {
        log::warn!(
            "XTCP owner: no valid visitor addresses for proxy {}",
            proxy.name
        );
        return;
    }

    let stream = match KcpStream::accept(socket, peers).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("XTCP owner kcp accept failed: {}", e);
            return;
        }
    };

    log::info!(
        "XTCP owner: waiting for hole punch from visitor for proxy {}",
        proxy.name
    );
    if !wait_kcp_active(&stream, std::time::Duration::from_secs(6)).await {
        log::info!(
            "XTCP owner: hole punch timeout for {}, visitor will fall back to STCP relay",
            proxy.name
        );
        return;
    }
    log::info!("XTCP P2P established for {} (owner side)", proxy.name);

    // 连接本地被代理服务
    let local_svc = format!("{}:{}", proxy.local_ip, proxy.local_port);
    let local_conn = match tokio::net::TcpStream::connect(&local_svc).await {
        Ok(c) => c,
        Err(e) => {
            log::error!(
                "XTCP owner connect local service {} failed: {}",
                local_svc,
                e
            );
            return;
        }
    };

    if let Err(e) = rust_frp_util::bridge_streams(stream, local_conn).await {
        log::debug!("XTCP owner bridge ended: {}", e);
    }
}

/// XTCP visitor 打洞尝试：
///
/// 返回 `None` 表示 P2P 成功（local_conn 已与 KCP 流桥接）；
/// 返回 `Some(local_conn)` 表示打洞失败，调用方继续走 STCP 服务器中继。
async fn xtcp_try_p2p(
    proxy_name: &str,
    msg_tx: &tokio::sync::mpsc::Sender<Message>,
    run_id: &str,
    secret_key: &str,
    registry: &XtcpRegistry,
    local_conn: tokio::net::TcpStream,
) -> Option<tokio::net::TcpStream> {
    // 1. 绑定 UDP socket（与 STUN 探测复用）
    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            log::warn!("XTCP visitor bind UDP failed: {}", e);
            return Some(local_conn);
        }
    };
    let public = stun_discover(&socket).await;
    let local_addr = local_endpoint_of(&socket).await;

    // 2. 注册等待 owner 回传地址
    let addr_rx = registry.register(proxy_name.to_string());

    // 3. 发送自己的 NAT info（携带 secret_key 签名，服务端校验 visitor 身份）
    let timestamp = get_timestamp();
    let sign_key = rust_frp_auth::generate_stcp_sign_key(secret_key, proxy_name, timestamp);
    let nat_info = rust_frp_core::XtcpNatInfoMsg {
        proxy_name: proxy_name.to_string(),
        run_id: run_id.to_string(),
        nat_type: "unknown".to_string(),
        local_addr,
        public_addr: public.as_ref().map(|a| a.to_string()).unwrap_or_default(),
        sign_key,
        timestamp,
    };
    if msg_tx.send(Message::XtcpNatInfo(nat_info)).await.is_err() {
        log::warn!("XTCP visitor: control channel closed, falling back");
        return Some(local_conn);
    }

    // 4. 等待 owner 的 NAT info（经服务器中继）
    let (owner_public, owner_local) =
        match tokio::time::timeout(std::time::Duration::from_secs(6), addr_rx).await {
            Ok(Ok(addrs)) => addrs,
            Ok(Err(_)) => {
                log::info!("XTCP visitor: pending session replaced, falling back");
                return Some(local_conn);
            }
            Err(_) => {
                log::info!(
                    "XTCP visitor: no owner NAT info in time for {}, falling back",
                    proxy_name
                );
                return Some(local_conn);
            }
        };

    let peers = parse_peer_addrs(&owner_public, &owner_local);
    if peers.is_empty() {
        log::info!(
            "XTCP visitor: owner has no reachable addresses for {}, falling back",
            proxy_name
        );
        return Some(local_conn);
    }

    // 5. 发起 KCP 打洞（connect 侧随机 conv，punch 包周期发送）
    log::info!(
        "XTCP visitor: hole punching for {} (peers: {:?})",
        proxy_name,
        peers
    );
    let conv = rand::random::<u32>();
    let stream = match KcpStream::connect(socket, peers, conv).await {
        Ok(s) => s,
        Err(e) => {
            log::warn!("XTCP visitor kcp connect failed: {}", e);
            return Some(local_conn);
        }
    };

    if !wait_kcp_active(&stream, std::time::Duration::from_secs(6)).await {
        log::info!(
            "XTCP visitor: hole punch timeout for {}, falling back to STCP relay",
            proxy_name
        );
        return Some(local_conn);
    }
    log::info!("XTCP P2P established for {} (visitor side)", proxy_name);

    // 6. P2P 桥接：本地连接 <-> KCP 流
    if let Err(e) = rust_frp_util::bridge_streams(stream, local_conn).await {
        log::debug!("XTCP visitor bridge ended: {}", e);
    }
    None
}

/// 启动 STCP/XTCP 访问者：监听本地端口，当有连接时创建到服务器的工作连接并桥接
async fn start_stcp_visitor(
    bind_addr: String,
    proxy_name: String,
    stcp_tx: tokio::sync::mpsc::Sender<Message>,
    run_id: String,
    config: Arc<ClientConfig>,
    work_conn_tls: bool,
    xtcp_registry: Arc<XtcpRegistry>,
) {
    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            log::error!(
                "Failed to bind STCP visitor {} on {}: {:?}",
                proxy_name,
                bind_addr,
                e
            );
            return;
        }
    };
    log::info!("STCP visitor for {} listening on {}", proxy_name, bind_addr);

    loop {
        match listener.accept().await {
            Ok((local_conn, addr)) => {
                log::info!(
                    "STCP visitor accepted connection from {} for {}",
                    addr,
                    proxy_name
                );
                let pn = proxy_name.clone();
                let tx = stcp_tx.clone();
                let rid = run_id.clone();
                let cfg = Arc::clone(&config);
                let wct = work_conn_tls;
                let reg = xtcp_registry.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_stcp_visitor_conn(local_conn, pn, tx, rid, cfg, wct, reg).await
                    {
                        log::error!("STCP visitor connection error: {:?}", e);
                    }
                });
            }
            Err(e) => {
                log::error!("STCP visitor accept error: {:?}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }
}

/// 处理单个 STCP/XTCP 访问者连接
/// XTCP 先走 STUN + KCP UDP 打洞尝试 P2P；失败/超时后回退 STCP 服务端中继
async fn handle_stcp_visitor_conn(
    local_conn: tokio::net::TcpStream,
    proxy_name: String,
    stcp_tx: tokio::sync::mpsc::Sender<Message>,
    run_id: String,
    config: Arc<ClientConfig>,
    work_conn_tls: bool,
    xtcp_registry: Arc<XtcpRegistry>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let is_xtcp = config
        .visitors
        .iter()
        .any(|v| v.server_name == proxy_name && v.r#type == "xtcp");

    // 访问者配置的 secret_key（需与服务端代理的 secret_key 一致）
    let secret_key = config
        .visitors
        .iter()
        .find(|v| v.server_name == proxy_name)
        .and_then(|v| v.secret_key.clone())
        .unwrap_or_default();

    // 应用层加密：需与对端代理的 use_encryption 配置一致（fail-closed）
    let use_encryption = config
        .visitors
        .iter()
        .find(|v| v.server_name == proxy_name)
        .map(|v| v.use_encryption)
        .unwrap_or(false);
    let use_compression = config
        .visitors
        .iter()
        .find(|v| v.server_name == proxy_name)
        .map(|v| v.use_compression)
        .unwrap_or(false);
    if use_encryption && config.auth.token.is_none() {
        return Err(format!(
            "visitor for [{}] enables use_encryption but client has no token configured",
            proxy_name
        )
        .into());
    }

    // XTCP：先尝试 P2P 打洞，成功则本地连接直接桥接到 KCP 流
    let local_conn = if is_xtcp {
        match xtcp_try_p2p(
            &proxy_name,
            &stcp_tx,
            &run_id,
            &secret_key,
            &xtcp_registry,
            local_conn,
        )
        .await
        {
            None => return Ok(()), // P2P 成功，桥接已在内部完成
            Some(conn) => {
                log::info!(
                    "XTCP P2P unavailable for {}, falling back to STCP relay",
                    proxy_name
                );
                conn
            }
        }
    } else {
        local_conn
    };

    // STCP/XTCP 访问签名：基于访问者配置的 secret_key（与服务端代理 secret_key 一致）
    // sign_key = Base64(HMAC-SHA256(secret_key, "stcp:{proxy_name}:{timestamp}"))
    let timestamp = get_timestamp();
    let sign_key = rust_frp_auth::generate_stcp_sign_key(&secret_key, &proxy_name, timestamp);

    let stcp_msg = rust_frp_core::StcpVisitorMsg {
        proxy_name: proxy_name.clone(),
        run_id: run_id.clone(),
        timestamp,
        sign_key,
    };

    if let Err(e) = stcp_tx.send(Message::StcpVisitor(stcp_msg)).await {
        return Err(format!("Failed to send StcpVisitor: {}", e).into());
    }

    // 工作连接：与 establish_work_connection 共用同一建立与包装逻辑
    let (work_conn, _, _) = open_work_conn(
        &config,
        WorkConnRequest {
            proxy_name: &proxy_name,
            run_id: &run_id,
            work_conn_tls,
            mux_session: None,
            use_encryption,
            use_compression,
        },
    )
    .await?;

    rust_frp_util::bridge_streams(work_conn, local_conn).await?;
    Ok(())
}

// ============ SUDP：UDP over 隧道（对齐原版 frp 的 sudp 代理/访问者） ============
//
// 服务端不解析 UDP：它只按 STCP 语义把两端的工作连接配对桥接，UDP 报文由
// 两个 frpc 用 `UdpPacketMsg` 帧在 TCP 隧道上承载。代理侧把每个访问者源
// 地址映射成一个独立的本地 UDP 会话；访问者侧每个本地 UDP 源地址占用一条
// 独立隧道，并在 60s 无消息（代理侧每 30s 心跳）后回收。

/// 访问者隧道心跳间隔（代理侧发送，用于让访问者感知隧道存活）
const SUDP_HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
/// 访问者隧道空闲上限（连续两个心跳周期无消息即判定会话结束）
const SUDP_TUNNEL_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// sudp 访问者会话表（会话任务自行摘除，避免陈旧会话常驻）
type SudpSessions = Arc<Mutex<std::collections::HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>;

/// 隧道写任务：从通道取消息写入已建立的工作连接
///
/// 返回发送端；写入失败时任务自行结束（后续发送返回错误，调用方据此回收会话）。
fn spawn_tunnel_writer<W>(mut writer: W) -> mpsc::Sender<Message>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::channel::<Message>(1024);
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = rust_frp_core::write_message(&mut writer, &msg).await {
                log::debug!("sudp: tunnel writer closed: {:?}", e);
                break;
            }
        }
    });
    tx
}

/// 代理侧心跳：周期性投递 Ping，供访问者侧判定隧道是否存活
///
/// 返回任务句柄，隧道读循环结束后由调用方 `abort`，避免半关闭场景下
/// 心跳任务持有的发送端让写任务无法退出。
fn spawn_sudp_heartbeat(out_tx: mpsc::Sender<Message>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SUDP_HEARTBEAT_INTERVAL);
        ticker.tick().await; // 跳过 interval 的立即首次 tick
        loop {
            ticker.tick().await;
            let ping = Message::Ping(rust_frp_core::PingMsg {
                timestamp: get_timestamp(),
            });
            if out_tx.send(ping).await.is_err() {
                break;
            }
        }
    })
}

/// sudp 代理侧：把工作连接上的 UDP 包帧转发到本地 UDP 服务
///
/// 每个访问者源地址对应一个独立本地 UDP 会话（连接到 `local_addr` 的临时
/// socket），保证本地服务回包能准确回到对应访问者。
async fn serve_sudp_proxy(
    work_conn: Box<dyn rust_frp_net::FrpConn>,
    proxy_name: &str,
    local_addr: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    log::info!(
        "sudp proxy {} tunnel established, forwarding to local udp {}",
        proxy_name,
        local_addr
    );

    let (mut reader, writer) = tokio::io::split(work_conn);
    let out_tx = spawn_tunnel_writer(writer);
    let heartbeat = spawn_sudp_heartbeat(out_tx.clone());

    let mut sessions: std::collections::HashMap<String, mpsc::Sender<Vec<u8>>> =
        std::collections::HashMap::new();

    loop {
        let msg = match rust_frp_core::read_message(&mut reader).await {
            Ok(msg) => msg,
            Err(e) => {
                log::debug!("sudp proxy {} tunnel closed: {:?}", proxy_name, e);
                break;
            }
        };
        let Message::UdpPacket(packet) = msg else {
            continue;
        };
        let Some(client_addr) = packet.client_addr else {
            continue;
        };

        let inbound = match sessions.get(&client_addr) {
            Some(tx) => tx.clone(),
            None => {
                let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
                spawn_sudp_local_session(
                    client_addr.clone(),
                    local_addr.clone(),
                    proxy_name.to_string(),
                    rx,
                    out_tx.clone(),
                );
                sessions.insert(client_addr.clone(), tx.clone());
                tx
            }
        };
        if inbound.send(packet.data).await.is_err() {
            sessions.remove(&client_addr);
        }
    }

    log::info!("sudp proxy {} tunnel ended", proxy_name);
    heartbeat.abort();
    Ok(())
}

/// 单个访问者对应的本地 UDP 会话：入站载荷 → 本地服务，回包 → 隧道
fn spawn_sudp_local_session(
    client_addr: String,
    local_addr: String,
    proxy_name: String,
    mut inbound: mpsc::Receiver<Vec<u8>>,
    out_tx: mpsc::Sender<Message>,
) {
    tokio::spawn(async move {
        let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(socket) => socket,
            Err(e) => {
                log::error!("sudp: bind local udp socket failed: {}", e);
                return;
            }
        };
        if let Err(e) = socket.connect(&local_addr).await {
            log::error!("sudp: connect local udp {} failed: {}", local_addr, e);
            return;
        }

        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                payload = inbound.recv() => {
                    let Some(data) = payload else { break };
                    if let Err(e) = socket.send(&data).await {
                        log::debug!("sudp: send to local {} failed: {}", local_addr, e);
                        break;
                    }
                }
                received = socket.recv(&mut buf) => {
                    match received {
                        Ok(n) => {
                            let msg = Message::UdpPacket(rust_frp_core::UdpPacketMsg {
                                proxy_name: proxy_name.clone(),
                                data: buf[..n].to_vec(),
                                client_addr: Some(client_addr.clone()),
                            });
                            if out_tx.send(msg).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            log::debug!("sudp: recv from local {} failed: {}", local_addr, e);
                            break;
                        }
                    }
                }
            }
        }
    });
}

/// sudp 访问者会话上下文（跨会话共享的不可变信息）
#[derive(Clone)]
struct SudpVisitorContext {
    proxy_name: String,
    run_id: String,
    config: Arc<ClientConfig>,
    work_conn_tls: bool,
    secret_key: String,
    use_encryption: bool,
    use_compression: bool,
    stcp_tx: mpsc::Sender<Message>,
    socket: Arc<tokio::net::UdpSocket>,
}

/// sudp 访问者：监听本地 UDP 端口，按源地址建立独立隧道会话
async fn start_sudp_visitor(
    bind_addr: String,
    proxy_name: String,
    stcp_tx: mpsc::Sender<Message>,
    run_id: String,
    config: Arc<ClientConfig>,
    work_conn_tls: bool,
) {
    let socket = match tokio::net::UdpSocket::bind(&bind_addr).await {
        Ok(socket) => Arc::new(socket),
        Err(e) => {
            log::error!(
                "Failed to bind sudp visitor {} on {}: {:?}",
                proxy_name,
                bind_addr,
                e
            );
            return;
        }
    };
    log::info!("sudp visitor for {} listening on {}", proxy_name, bind_addr);

    let visitor_cfg = config.visitors.iter().find(|v| v.server_name == proxy_name);
    let ctx = SudpVisitorContext {
        secret_key: visitor_cfg
            .and_then(|v| v.secret_key.clone())
            .unwrap_or_default(),
        use_encryption: visitor_cfg.map(|v| v.use_encryption).unwrap_or(false),
        use_compression: visitor_cfg.map(|v| v.use_compression).unwrap_or(false),
        proxy_name,
        run_id,
        config,
        work_conn_tls,
        stcp_tx,
        socket: socket.clone(),
    };

    let sessions: SudpSessions = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let mut buf = vec![0u8; 65535];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, src)) => {
                let data = buf[..n].to_vec();
                let existing = { sessions.lock().await.get(&src).cloned() };
                let inbound = match existing {
                    Some(tx) => tx,
                    None => match sudp_open_session(&ctx, src, sessions.clone()).await {
                        Ok(tx) => {
                            sessions.lock().await.insert(src, tx.clone());
                            tx
                        }
                        Err(e) => {
                            log::warn!("sudp visitor session for {} failed: {}", src, e);
                            continue;
                        }
                    },
                };
                if inbound.send(data).await.is_err() {
                    sessions.lock().await.remove(&src);
                }
            }
            Err(e) => {
                log::error!("sudp visitor recv error: {:?}", e);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// 打开一个 sudp 访问者隧道会话
///
/// 先向服务端登记访问请求（服务端据此创建桥接并通知代理侧建工作连接），
/// 再建立工作连接。会话在读循环退出（隧道关闭或心跳超时）时自行从
/// `sessions` 中摘除，避免陈旧会话常驻。
async fn sudp_open_session(
    ctx: &SudpVisitorContext,
    src: SocketAddr,
    sessions: SudpSessions,
) -> Result<mpsc::Sender<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    // 与服务端代理 secret_key 一致的访问签名（服务端 fail-closed 校验）
    let timestamp = get_timestamp();
    let sign_key =
        rust_frp_auth::generate_stcp_sign_key(&ctx.secret_key, &ctx.proxy_name, timestamp);
    ctx.stcp_tx
        .send(Message::StcpVisitor(rust_frp_core::StcpVisitorMsg {
            proxy_name: ctx.proxy_name.clone(),
            run_id: ctx.run_id.clone(),
            timestamp,
            sign_key,
        }))
        .await
        .map_err(|e| format!("Failed to send StcpVisitor for sudp: {}", e))?;

    let (work_conn, _, _) = open_work_conn(
        &ctx.config,
        WorkConnRequest {
            proxy_name: &ctx.proxy_name,
            run_id: &ctx.run_id,
            work_conn_tls: ctx.work_conn_tls,
            mux_session: None,
            use_encryption: ctx.use_encryption,
            use_compression: ctx.use_compression,
        },
    )
    .await?;

    log::info!(
        "sudp visitor tunnel established for {} (client {})",
        ctx.proxy_name,
        src
    );

    let (mut reader, writer) = tokio::io::split(work_conn);
    let out_tx = spawn_tunnel_writer(writer);

    // 出站：本地 UDP 载荷 → UDP 包帧（会话与源地址一一对应，故回程目标固定为 src）
    let (inbound_tx, mut inbound_rx) = mpsc::channel::<Vec<u8>>(256);
    {
        let proxy_name = ctx.proxy_name.clone();
        tokio::spawn(async move {
            while let Some(data) = inbound_rx.recv().await {
                let msg = Message::UdpPacket(rust_frp_core::UdpPacketMsg {
                    proxy_name: proxy_name.clone(),
                    data,
                    client_addr: Some(src.to_string()),
                });
                if out_tx.send(msg).await.is_err() {
                    break;
                }
            }
        });
    }

    // 入站：隧道 → 本地访问者；60s 无消息（含心跳）即判定会话结束
    let socket = ctx.socket.clone();
    let proxy_name = ctx.proxy_name.clone();
    tokio::spawn(async move {
        loop {
            let received = tokio::time::timeout(
                SUDP_TUNNEL_IDLE_TIMEOUT,
                rust_frp_core::read_message(&mut reader),
            )
            .await;
            match received {
                Ok(Ok(Message::UdpPacket(packet))) => {
                    if let Err(e) = socket.send_to(&packet.data, src).await {
                        log::debug!("sudp visitor send_to {} failed: {}", src, e);
                    }
                }
                // Ping 等控制消息不转发
                Ok(Ok(_)) => continue,
                Ok(Err(e)) => {
                    log::debug!("sudp visitor tunnel closed for {}: {:?}", proxy_name, e);
                    break;
                }
                Err(_) => {
                    log::debug!("sudp visitor tunnel idle timeout for {}", proxy_name);
                    break;
                }
            }
        }
        sessions.lock().await.remove(&src);
        log::info!("sudp visitor session for {} closed", src);
    });

    Ok(inbound_tx)
}

/// Web 服务器（frpc 管理 API）
///
/// 路由：
/// - `GET  /health`   存活探针
/// - `GET  /proxies`  代理配置列表
/// - `GET  /visitors` 访客配置列表
/// - `GET  /status`   代理/访客运行状态（`frpc status` 使用）
/// - `POST /reload`   触发配置热重载（`frpc reload` 使用）
/// - `GET  /config`   读取配置文件原文（对齐原版 `GET /api/config`）
/// - `PUT  /config`   校验并原子覆写配置文件 + 触发热重载（对齐原版 `PUT /api/config`）
///
/// 配置了 `webServer.user` + `webServer.password` 时全部端点要求
/// Basic 认证（常量时间比较）；未配置则保持开放（向后兼容）。
/// `/config` 读写端点因涉及 token 等敏感内容与配置文件覆写，在未配置
/// 认证时直接 403 禁用（fail-closed）。
pub struct WebServer {
    addr: SocketAddr,
    /// Basic 认证凭据（user, password），None 表示不启用
    auth: Option<(String, String)>,
    server: Option<tokio::task::JoinHandle<()>>,
}

/// Web 服务器共享状态
#[derive(Clone)]
struct WebServerState {
    proxy_manager: Arc<ClientProxyManager>,
    visitor_manager: Arc<ClientVisitorManager>,
    /// reload 端点通过该 Notify 通知 Client 主循环执行 reload_config
    reload_notify: Arc<tokio::sync::Notify>,
    /// 配置文件路径（PUT /config 原子落盘的目标；None 表示管理端不可用）
    config_path: Option<String>,
    /// webServer 是否配置了 user/password（config 端点在 false 时直接 403）
    auth_enabled: bool,
}

impl WebServer {
    pub fn new(
        config: &rust_frp_config::WebServerConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let addr = format!("{}:{}", config.addr, config.port).parse::<SocketAddr>()?;
        // user/password 必须成对配置才启用 Basic 认证；只配一个视为未配置
        let auth = match (config.user.as_deref(), config.password.as_deref()) {
            (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => {
                Some((u.to_string(), p.to_string()))
            }
            _ => None,
        };
        Ok(Self {
            addr,
            auth,
            server: None,
        })
    }

    pub async fn start(&mut self, client: &Client) -> Result<(), Box<dyn std::error::Error>> {
        let state = Arc::new(WebServerState {
            proxy_manager: client.proxy_manager.clone(),
            visitor_manager: client.visitor_manager.clone(),
            reload_notify: client.reload_notify.clone(),
            config_path: client.config_path.clone(),
            auth_enabled: self.auth.is_some(),
        });

        let auth = self.auth.clone();
        let app = Router::new()
            .route("/health", get(health_handler))
            .route("/proxies", get(proxies_handler))
            .route("/visitors", get(visitors_handler))
            .route("/status", get(status_handler))
            .route("/reload", post(reload_handler))
            .route("/config", get(get_config_handler).put(put_config_handler))
            .with_state(state)
            .layer(middleware::from_fn(move |req, next| {
                basic_auth_middleware(req, next, auth.clone())
            }));

        let listener = tokio::net::TcpListener::bind(self.addr).await?;
        let handle = tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                log::error!("Web server error: {:?}", e);
            }
        });
        self.server = Some(handle);

        Ok(())
    }
}

/// Basic 认证中间件：未配置凭据直接放行；配置后校验（常量时间比较）
async fn basic_auth_middleware(
    req: Request,
    next: Next,
    expected: Option<(String, String)>,
) -> Response {
    let Some((user, password)) = expected else {
        return next.run(req).await;
    };

    let authorized = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_basic_credentials)
        .map(|(u, p)| {
            rust_frp_auth::constant_time_compare(u.as_bytes(), user.as_bytes())
                && rust_frp_auth::constant_time_compare(p.as_bytes(), password.as_bytes())
        })
        .unwrap_or(false);

    if authorized {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [("WWW-Authenticate", "Basic realm=\"frpc admin\"")],
        )
            .into_response()
    }
}

/// 解析 `Authorization: Basic <base64(user:password)>` 头
fn parse_basic_credentials(value: &str) -> Option<(String, String)> {
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = base64::decode(encoded).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (user, password) = decoded.split_once(':')?;
    Some((user.to_string(), password.to_string()))
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "timestamp": get_timestamp(),
    }))
}

async fn proxies_handler(
    State(state): State<Arc<WebServerState>>,
) -> Json<Vec<rust_frp_config::ProxyConfig>> {
    let proxies = state.proxy_manager.proxies.read().await;
    Json(proxies.values().cloned().collect())
}

async fn visitors_handler(
    State(state): State<Arc<WebServerState>>,
) -> Json<Vec<rust_frp_config::VisitorConfig>> {
    let visitors = state.visitor_manager.visitors.read().await;
    Json(visitors.values().cloned().collect())
}

/// `GET /status`：代理/访客运行状态（对齐 frp 原版 `frpc status` 的语义）
async fn status_handler(State(state): State<Arc<WebServerState>>) -> Json<serde_json::Value> {
    let proxies = state.proxy_manager.proxies.read().await;
    let proxy_names: Vec<(String, String, u16, Option<u16>)> = proxies
        .values()
        .map(|p| {
            (
                p.name.clone(),
                p.r#type.clone(),
                p.local_port,
                p.remote_port,
            )
        })
        .collect();
    drop(proxies);

    let mut proxy_list: Vec<serde_json::Value> = Vec::with_capacity(proxy_names.len());
    for (name, proxy_type, local_port, remote_port) in proxy_names {
        // 累计流量（客户端视角）：down = 服务端→本地，up = 本地→服务端
        let (bytes_down, bytes_up) = state
            .proxy_manager
            .traffic_snapshot(&name)
            .await
            .unwrap_or((0, 0));
        proxy_list.push(serde_json::json!({
            "name": name,
            "type": proxy_type,
            "status": "running",
            "local_port": local_port,
            "remote_port": remote_port,
            "traffic_down": bytes_down,
            "traffic_up": bytes_up,
        }));
    }

    let visitors = state.visitor_manager.visitors.read().await;
    let visitor_list: Vec<serde_json::Value> = visitors
        .values()
        .map(|v| {
            serde_json::json!({
                "name": v.name,
                "type": v.r#type,
                "server_name": v.server_name,
                "status": "running",
            })
        })
        .collect();
    drop(visitors);

    Json(serde_json::json!({
        "proxies": proxy_list,
        "visitors": visitor_list,
    }))
}

/// `POST /reload`：通知 Client 主循环重读配置并重新注册代理/访客。
///
/// 通知是异步投递（Notify 许可位语义），端点返回时 reload 尚未完成，
/// 与 frp 原版同步等待 reload 结束的语义略有差异。
async fn reload_handler(State(state): State<Arc<WebServerState>>) -> Json<serde_json::Value> {
    state.reload_notify.notify_one();
    Json(serde_json::json!({
        "msg": "reload signal sent",
        "code": 200,
    }))
}

/// config 端点的前置守卫：未启用认证或未提供配置路径时拒绝
fn config_endpoint_guard(state: &WebServerState) -> Result<String, Box<Response>> {
    if !state.auth_enabled {
        return Err(Box::new(
            (
                StatusCode::FORBIDDEN,
                "config API is disabled: configure webServer.user/password first \
                 (config content contains auth token)"
                    .to_string(),
            )
                .into_response(),
        ));
    }
    let Some(path) = state.config_path.clone() else {
        return Err(Box::new(
            (
                StatusCode::FORBIDDEN,
                "config API is unavailable: frpc was started without a config file path"
                    .to_string(),
            )
                .into_response(),
        ));
    };
    Ok(path)
}

/// `GET /config`：返回配置文件原文（text/plain）
async fn get_config_handler(State(state): State<Arc<WebServerState>>) -> Response {
    let path = match config_endpoint_guard(&state) {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => (
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            content,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("read config failed: {e}"),
        )
            .into_response(),
    }
}

/// `PUT /config`：校验请求体为新配置 → 原子覆写配置文件 → 触发热重载。
///
/// 语义对齐原版 frp 的 `PUT /api/config`：写盘成功即返回 200，重载由
/// reload 通道异步完成；校验失败返回 400 且不落盘（原文件保持不动）。
async fn put_config_handler(State(state): State<Arc<WebServerState>>, body: String) -> Response {
    let path = match config_endpoint_guard(&state) {
        Ok(p) => p,
        Err(resp) => return *resp,
    };

    // 先整体校验（解析 + 归并 + 规则校验），失败不落盘
    if let Err(e) = rust_frp_config::ConfigLoader::validate_client_config_content(&body) {
        return (
            StatusCode::BAD_REQUEST,
            format!("config validation failed: {e}"),
        )
            .into_response();
    }

    // 原子写：临时文件 + rename，避免写一半崩溃留下残缺配置
    let tmp_path = format!("{}.tmp-{}", path, rand_id(8));
    if let Err(e) = tokio::fs::write(&tmp_path, &body).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("write config failed: {e}"),
        )
            .into_response();
    }
    if let Err(e) = tokio::fs::rename(&tmp_path, &path).await {
        // rename 失败时清理临时文件，避免残留
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("rename config failed: {e}"),
        )
            .into_response();
    }

    log::info!("config updated via admin API, triggering reload");
    state.reload_notify.notify_one();
    Json(serde_json::json!({
        "msg": "config updated, reload triggered",
        "code": 200,
    }))
    .into_response()
}

/// 健康检查器
///
/// 定期检查后端服务健康状态，支持 TCP 和 HTTP 两种检查方式。
pub struct HealthChecker {
    config: rust_frp_config::ProxyConfig,
}

impl HealthChecker {
    pub fn new(config: rust_frp_config::ProxyConfig) -> Self {
        Self { config }
    }

    pub fn start(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let hc = self.config.health_check.as_ref();
            let hc = match hc {
                Some(c) => c,
                None => return,
            };

            let interval = tokio::time::Duration::from_secs(hc.interval_seconds.max(1) as u64);
            let timeout = tokio::time::Duration::from_secs(hc.timeout_seconds.max(1) as u64);
            let max_failed = hc.max_failed;
            let check_type = hc.r#type.clone();
            let path = hc.path.clone();
            let target_addr = format!("{}:{}", self.config.local_ip, self.config.local_port);
            let mut failed_count: u32 = 0;

            loop {
                tokio::time::sleep(interval).await;

                match check_type.as_str() {
                    "tcp" => {
                        let result = tokio::time::timeout(
                            timeout,
                            tokio::net::TcpStream::connect(&target_addr),
                        )
                        .await;
                        match result {
                            Ok(Ok(_)) => {
                                if failed_count > 0 {
                                    log::warn!(
                                        "Health check for proxy '{}' recovered (TCP: {})",
                                        self.config.name,
                                        target_addr
                                    );
                                }
                                failed_count = 0;
                            }
                            _ => {
                                failed_count += 1;
                                log::warn!(
                                    "Health check for proxy '{}' failed ({}/{}): TCP connect to {}",
                                    self.config.name,
                                    failed_count,
                                    max_failed,
                                    target_addr
                                );
                                if failed_count >= max_failed {
                                    log::error!(
                                        "Health check for proxy '{}' exceeded max failures, service marked unhealthy",
                                        self.config.name
                                    );
                                    failed_count = 0;
                                }
                            }
                        }
                    }
                    "http" => {
                        let path = path.clone().unwrap_or_else(|| "/".to_string());
                        let result = tokio::time::timeout(timeout, async {
                            let stream = tokio::net::TcpStream::connect(&target_addr).await?;
                            let (mut reader, mut writer) =
                                tokio::io::split(tokio::io::BufStream::new(stream));
                            use tokio::io::AsyncReadExt;
                            use tokio::io::AsyncWriteExt;

                            let request = format!(
                                "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
                                path, self.config.local_ip
                            );
                            writer.write_all(request.as_bytes()).await?;

                            let mut response = String::new();
                            reader.read_to_string(&mut response).await?;

                            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(response)
                        })
                        .await;

                        match result {
                            Ok(Ok(response)) => {
                                if response.contains("200 OK") || response.contains("HTTP/1.") {
                                    if failed_count > 0 {
                                        log::warn!(
                                            "Health check for proxy '{}' recovered (HTTP: {})",
                                            self.config.name,
                                            target_addr
                                        );
                                    }
                                    failed_count = 0;
                                } else {
                                    failed_count += 1;
                                    log::warn!(
                                        "Health check for proxy '{}' failed ({}/{}): HTTP unexpected response",
                                        self.config.name, failed_count, max_failed
                                    );
                                    if failed_count >= max_failed {
                                        log::error!(
                                            "Health check for proxy '{}' exceeded max failures, service marked unhealthy",
                                            self.config.name
                                        );
                                        failed_count = 0;
                                    }
                                }
                            }
                            _ => {
                                failed_count += 1;
                                log::warn!(
                                    "Health check for proxy '{}' failed ({}/{}): HTTP request to {}",
                                    self.config.name, failed_count, max_failed, target_addr
                                );
                                if failed_count >= max_failed {
                                    log::error!(
                                        "Health check for proxy '{}' exceeded max failures, service marked unhealthy",
                                        self.config.name
                                    );
                                    failed_count = 0;
                                }
                            }
                        }
                    }
                    _ => {
                        log::warn!(
                            "Unsupported health check type '{}' for proxy '{}'",
                            check_type,
                            self.config.name
                        );
                        break;
                    }
                }
            }
        })
    }
}

/// 客户端服务
pub struct Client {
    config: Arc<ClientConfig>,
    control: Option<Mutex<ClientControl>>,
    proxy_manager: Arc<ClientProxyManager>,
    visitor_manager: Arc<ClientVisitorManager>,
    auth_manager: Arc<AuthManager>,
    work_conn_manager: Arc<WorkConnManager>,
    connector: Connector,
    web_server: Option<WebServer>,
    /// 管理端 POST /reload 经由此通知主循环执行 reload_config
    reload_notify: Arc<tokio::sync::Notify>,
    config_path: Option<String>,
    health_check_handles: Vec<tokio::task::JoinHandle<()>>,
}

impl Client {
    pub fn new(
        mut config: ClientConfig,
        config_path: Option<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // client_id 是客户端进程的稳定标识（断线重连时复用，服务端据此
        // 把同 client_id 的新登录判定为重连并踢掉旧会话）。默认必须随机
        // 生成而非用主机名：同一台机器运行多个 frpc 时主机名相同，会被
        // 服务端误判为同一客户端重连而互相踢下线
        if config.client_id.is_none() {
            config.client_id = Some(rand_id(16));
        }

        let auth_manager = Arc::new(AuthManager::new(&config.auth).map_err(|e| e.to_string())?);

        // 先创建可变的 proxy_manager，设置 work_conn_manager，再包装成 Arc
        let mut proxy_manager_instance = ClientProxyManager::new();
        let work_conn_manager = Arc::new(WorkConnManager::new());
        proxy_manager_instance.set_work_conn_manager(work_conn_manager.clone());
        proxy_manager_instance
            .set_default_bandwidth_limit(config.transport.bandwidth_limit.clone());
        let proxy_manager = Arc::new(proxy_manager_instance);

        let visitor_manager = Arc::new(ClientVisitorManager::new());

        // 配置整体以 Arc 共享：控制连接、工作连接、STCP visitor 等热路径
        // 只克隆指针而非深拷贝整个 ClientConfig
        let config = Arc::new(config);
        let connector = Connector::new(Arc::clone(&config))?;

        let mut web_server = None;
        if config.web_server.port > 0 {
            web_server = Some(WebServer::new(&config.web_server)?);
        }

        Ok(Self {
            config,
            control: None,
            proxy_manager,
            visitor_manager,
            auth_manager,
            work_conn_manager,
            connector,
            web_server,
            reload_notify: Arc::new(tokio::sync::Notify::new()),
            config_path,
            health_check_handles: Vec::new(),
        })
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // 启动 Web 服务器
        if let Some(mut web_server) = self.web_server.take() {
            web_server.start(self).await.map_err(|e| e.to_string())?;
            log::info!("web server started");
            self.web_server = Some(web_server);
        }

        // 设置信号处理
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;

        // 配置文件变更触发热重载（与管理端 /reload、SIGHUP 共用通知通道）
        if let Some(watch_path) = self.config_path.clone() {
            let reload_notify = Arc::clone(&self.reload_notify);
            tokio::spawn(async move {
                use notify::{Event, EventKind, RecursiveMode, Watcher};
                let (watch_tx, mut watch_rx) = tokio::sync::mpsc::channel(1);
                let mut watcher =
                    match notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
                        if let Ok(event) = res {
                            if matches!(event.kind, EventKind::Modify(_)) {
                                let _ = watch_tx.blocking_send(());
                            }
                        }
                    }) {
                        Ok(w) => w,
                        Err(e) => {
                            log::warn!("Failed to create file watcher: {}", e);
                            return;
                        }
                    };

                if let Err(e) = watcher.watch(
                    std::path::Path::new(&watch_path),
                    RecursiveMode::NonRecursive,
                ) {
                    log::warn!("Failed to watch config file {}: {}", watch_path, e);
                    return;
                }
                log::info!("Watching config file for changes: {}", watch_path);

                loop {
                    if watch_rx.recv().await.is_none() {
                        break;
                    }
                    // 500ms 防抖：编辑器保存常产生多次 Modify 事件
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    log::info!("Config file changed, triggering config reload...");
                    reload_notify.notify_one();
                }
            });
        }

        // 重连配置：首次断线立即重连（0ms），失败后 1s 起步指数退避，封顶 30s
        let mut reconnect_delay_ms: u64 = 0;
        let max_reconnect_delay_ms: u64 = 30_000;

        // 热重载通知：管理端 POST /reload、SIGHUP、配置文件变更共用同一通道
        let reload_notify = Arc::clone(&self.reload_notify);
        let mut reload_requested = false;

        log::info!("Client started, entering main loop with auto-reconnect...");

        loop {
            tokio::select! {
                // 主重连循环
                _ = async {
                    // 登录到服务器
                    if let Err(e) = self.login().await {
                        log::error!("Login failed: {}", e);
                        return;
                    }

                    // 登录成功：重置退避，下次断线仍然立即重连
                    reconnect_delay_ms = 0;

                    // 克隆代理配置到临时向量
                    let proxies = self.config.proxies.clone();

                    log::info!("Number of proxies: {}", proxies.len());

                    // 注册所有代理
                    for proxy in &proxies {
                        log::info!("Registering proxy: {}", proxy.name);
                        if let Err(e) = self.register_proxy(proxy).await {
                            log::error!("Failed to register proxy {}: {}", proxy.name, e);
                        }
                    }

                    // 启动所有代理
                    for proxy in &proxies {
                        log::info!("Starting proxy: {} on local port {}", proxy.name, proxy.local_port);
                        if let Err(e) = self.proxy_manager.add_proxy(proxy.clone()).await {
                            log::error!("Failed to add proxy {}: {}", proxy.name, e);
                        }
                    }

                    // 启动所有访问者
                    for visitor in &self.config.visitors {
                        if let Err(e) = self.visitor_manager.add_visitor(visitor.clone()).await {
                            log::error!("Failed to add visitor: {}", e);
                        }
                    }

                    // 启动 STCP/XTCP 访问者监听器
                    if let Some(control) = &self.control {
                        let control = control.lock().await;
                        let stcp_tx = control.stcp_visitor_sender();
                        let run_id = control.run_id.clone();
                        let work_conn_tls = control.work_conn_tls();
                        let xtcp_registry = control.xtcp_registry();
                        drop(control);
                        for visitor in &self.config.visitors {
                            match visitor.r#type.as_str() {
                                "stcp" | "xtcp" => {
                                    let bind_addr =
                                        format!("{}:{}", visitor.bind_addr, visitor.bind_port);
                                    let proxy_name = visitor.server_name.clone();
                                    let stcp_tx = stcp_tx.clone();
                                    let cfg = Arc::clone(&self.config);
                                    let rid = run_id.clone();
                                    let reg = xtcp_registry.clone();
                                    tokio::spawn(async move {
                                        start_stcp_visitor(bind_addr, proxy_name, stcp_tx, rid, cfg, work_conn_tls, reg).await;
                                    });
                                }
                                // sudp visitor：监听本地 UDP，按源地址建独立隧道会话
                                "sudp" => {
                                    let bind_addr =
                                        format!("{}:{}", visitor.bind_addr, visitor.bind_port);
                                    let proxy_name = visitor.server_name.clone();
                                    let stcp_tx = stcp_tx.clone();
                                    let cfg = Arc::clone(&self.config);
                                    let rid = run_id.clone();
                                    tokio::spawn(async move {
                                        start_sudp_visitor(bind_addr, proxy_name, stcp_tx, rid, cfg, work_conn_tls).await;
                                    });
                                }
                                _ => {}
                            }
                        }
                    }

                    // 启动健康检查
                    self.stop_health_checks().await;
                    self.start_health_checks(&proxies).await;

                    // 运行控制循环
                    if let Some(control) = &self.control {
                        let mut control = control.lock().await;
                        if let Err(e) = control.run().await {
                            log::error!("Control loop error: {:?}", e);
                        }
                    }
                } => {
                    // 连接断开
                }
                // 热重载（管理端 /reload、SIGHUP、配置文件变更）
                _ = reload_notify.notified() => {
                    reload_requested = true;
                }
                _ = sighup.recv() => {
                    log::info!("Received SIGHUP, triggering config reload...");
                    reload_requested = true;
                }
                // 信号处理
                _ = sigint.recv() => {
                    log::info!("Received SIGINT, shutting down gracefully...");
                    self.graceful_shutdown().await?;
                    break;
                }
                _ = sigterm.recv() => {
                    log::info!("Received SIGTERM, shutting down gracefully...");
                    self.graceful_shutdown().await?;
                    break;
                }
            }

            if reload_requested {
                reload_requested = false;
                log::info!("Reloading config...");
                // reload_config 会重读配置并重新 add 代理/访客；随后走下方的
                // clear 重连路径按新配置整体重新注册，保证已删除的代理被下线
                if let Err(e) = self.reload_config().await {
                    log::error!("Reload config failed: {}", e);
                }
            } else {
                // 重连逻辑：登录失败与连接断开一致，均按退避重试（不退出进程），
                // 避免服务端暂时不可达时 frpc 直接死亡（信号分支自行 break）
                // jitter 与 frp 原版一致：在退避延迟上叠加 0~10% 随机量，
                // 防止服务端恢复时所有客户端同时涌入（惊群）
                let sleep_ms = if reconnect_delay_ms == 0 {
                    0
                } else {
                    let jitter = (reconnect_delay_ms as f64 * rand::random::<f64>() * 0.1) as u64;
                    reconnect_delay_ms + jitter
                };
                log::warn!(
                    "Connection lost, attempting to reconnect in {} ms...",
                    sleep_ms
                );
                tokio::time::sleep(tokio::time::Duration::from_millis(sleep_ms)).await;

                // 下次延迟：首次(0)后从 1s 起步翻倍，封顶 30s
                // （修复原实现 0*2=0 导致退避永不生效的问题）
                reconnect_delay_ms = if reconnect_delay_ms == 0 {
                    1_000
                } else {
                    (reconnect_delay_ms * 2).min(max_reconnect_delay_ms)
                };
            }

            // 重置代理管理器状态
            self.proxy_manager.clear().await;
            self.visitor_manager.clear().await;
        }

        log::info!("Client shutdown completed");
        Ok(())
    }

    async fn graceful_shutdown(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("Sending disconnect message to server...");

        if let Some(control) = &self.control {
            let mut control = control.lock().await;
            let disconnect_msg = rust_frp_core::DisconnectMsg {
                reason: "client_shutdown".to_string(),
            };
            if let Err(e) = control
                .conn
                .write_message(&Message::Disconnect(disconnect_msg))
                .await
            {
                log::warn!("Failed to send disconnect message: {:?}", e);
            } else {
                log::info!("Disconnect message sent successfully");
            }
        }

        log::info!("Graceful shutdown completed");
        Ok(())
    }

    async fn register_proxy(
        &mut self,
        proxy: &rust_frp_config::ProxyConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(control) = &self.control {
            let mut control = control.lock().await;
            // 发送代理注册消息
            let register_proxy_msg = rust_frp_core::RegisterProxyMsg {
                proxy: proxy.clone(),
            };
            control
                .conn
                .write_message(&Message::RegisterProxy(register_proxy_msg))
                .await?;

            // 读取注册响应
            let msg = control.conn.read_message().await?;
            match msg {
                Message::RegisterProxyResp(resp) => {
                    if !resp.error.is_empty() {
                        return Err(Box::new(std::io::Error::other(format!(
                            "Failed to register proxy {}: {}",
                            proxy.name, resp.error
                        ))));
                    }
                    log::info!("Proxy registered successfully: {}", proxy.name);
                }
                _ => {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Unexpected message",
                    )));
                }
            }
        }
        Ok(())
    }

    async fn login(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 根据传输协议选择连接方式
        let protocol = self.config.transport.protocol.as_str();
        let use_tls = self
            .config
            .transport
            .tls
            .as_ref()
            .map(|t| t.enable)
            .unwrap_or(true);

        let (mut conn, mux_session): (ControlConn, Option<Arc<MuxSession>>) = match protocol {
            "kcp" => {
                let kcp_conn = self
                    .connector
                    .connect_kcp()
                    .await
                    .map_err(|e| format!("KCP connection failed: {}", e))?;
                (ControlConn::new(Box::new(kcp_conn)), None)
            }
            "websocket" => {
                let scheme = if use_tls { "wss" } else { "ws" };
                let port = self.config.server_port;
                let url = format!("{}://{}:{}/ws", scheme, self.config.server_addr, port);
                let ws_conn = self
                    .connector
                    .connect_websocket(&url)
                    .await
                    .map_err(|e| format!("WebSocket connection failed: {}", e))?;
                (ControlConn::new(Box::new(ws_conn)), None)
            }
            _ if self.config.transport.tcp_mux => {
                // tcp_mux：TCP → magic 字节 → (TLS) → yamux 会话 → 首条流为控制流
                //（仅 TCP 协议生效，与 frp 原版语义一致）
                let addr = format!("{}:{}", self.config.server_addr, self.config.server_port)
                    .parse::<SocketAddr>()?;
                let mut tcp = tokio::net::TcpStream::connect(addr)
                    .await
                    .map_err(|e| format!("TCP connection failed: {}", e))?;
                // 先写 magic 字节，服务端嗅探后走多路复用路径（须在 TLS 握手前）
                tcp.write_all(&[TCP_MUX_MAGIC]).await?;
                log::info!("tcp_mux enabled, sent magic byte to server");

                let io: rust_frp_net::AnyConn = if use_tls {
                    let tls_config = build_client_tls_config(&self.config)
                        .map_err(|e| format!("failed to build client TLS config: {}", e))?
                        .ok_or("tcp_mux requires TLS but client tls is disabled")?;
                    let tls_stream = tls_config
                        .connect(&self.config.server_addr, tcp)
                        .await
                        .map_err(|e| format!("TLS connection failed: {}", e))?;
                    Box::new(tls_stream)
                } else {
                    Box::new(tcp)
                };

                let session = MuxSession::new_client(io);
                // 首条流 = 控制流（服务端 accept 后作为控制连接处理）
                let control_stream = session
                    .open_stream()
                    .await
                    .map_err(|e| format!("mux open control stream failed: {}", e))?;
                (ControlConn::new(control_stream), Some(session))
            }
            _ => {
                // 默认使用 TCP (可能带 TLS)
                if use_tls {
                    let tls_conn = self
                        .connector
                        .connect_tls(&self.config.server_addr)
                        .await
                        .map_err(|e| format!("TLS connection failed: {}", e))?;
                    (ControlConn::new(Box::new(tls_conn)), None)
                } else {
                    let tcp_conn = self
                        .connector
                        .connect()
                        .await
                        .map_err(|e| format!("TCP connection failed: {}", e))?;
                    (ControlConn::new(Box::new(tcp_conn)), None)
                }
            }
        };

        // 生成运行 ID
        let run_id = rand_id(16);

        // 获取主机名
        let hostname = hostname::get()?.to_string_lossy().to_string();

        // 创建登录消息
        let login_msg = rust_frp_core::LoginMsg {
            arch: std::env::consts::ARCH.to_string(),
            os: std::env::consts::OS.to_string(),
            hostname: hostname.clone(),
            pool_count: self.config.transport.pool_count,
            user: self.config.user.clone().unwrap_or_default(),
            client_id: self.config.client_id.clone().unwrap_or(hostname),
            version: "0.1.0".to_string(),
            timestamp: get_timestamp(),
            run_id: run_id.clone(),
            // token 认证 → 静态令牌；oidc 认证 → 向 IdP 现取 access_token
            token: resolve_auth_token(&self.config).await?,
            metas: std::collections::HashMap::new(),
            client_spec: None,
        };

        // 发送登录消息
        conn.write_message(&Message::Login(login_msg)).await?;

        // 读取登录响应
        let msg = conn.read_message().await?;
        match msg {
            Message::LoginResp(login_resp_msg) => {
                if !login_resp_msg.error.is_empty() {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        login_resp_msg.error,
                    )));
                }

                // 创建客户端控制（work_conn_tls 来自服务器协商）
                let work_conn_tls = login_resp_msg.work_conn_tls;
                if work_conn_tls {
                    log::info!("Server negotiated TLS for work connections");
                }
                let control = ClientControl::new(ClientControlDeps {
                    conn,
                    run_id: login_resp_msg.run_id,
                    proxy_manager: Arc::clone(&self.proxy_manager),
                    visitor_manager: Arc::clone(&self.visitor_manager),
                    auth_manager: Arc::clone(&self.auth_manager),
                    work_conn_manager: Arc::clone(&self.work_conn_manager),
                    config: Arc::clone(&self.config),
                    work_conn_tls,
                    mux_session,
                });
                self.control = Some(Mutex::new(control));

                log::info!("login to server success, run_id: {}", run_id);
            }
            _ => {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unexpected message",
                )));
            }
        }

        Ok(())
    }

    pub async fn start_health_checks(&mut self, proxies: &[rust_frp_config::ProxyConfig]) {
        for proxy in proxies {
            if proxy.health_check.is_some() {
                log::info!(
                    "Starting health check for proxy '{}' (type: {:?})",
                    proxy.name,
                    proxy.health_check.as_ref().map(|c| c.r#type.as_str())
                );
                let checker = HealthChecker::new(proxy.clone());
                let handle = checker.start();
                self.health_check_handles.push(handle);
            }
        }
    }

    pub async fn stop_health_checks(&mut self) {
        for handle in self.health_check_handles.drain(..) {
            handle.abort();
        }
    }

    /// 外部触发一次配置热重载（SIGHUP/配置文件监听与管理端 /reload 共用通道）
    pub fn notify_reload(&self) {
        self.reload_notify.notify_one();
    }

    pub async fn reload_config(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(config_path) = &self.config_path {
            let new_config = rust_frp_config::ConfigLoader::load_client_config(config_path)?;
            self.config = Arc::new(new_config);

            // 重新启动所有代理
            for proxy in &self.config.proxies {
                self.proxy_manager
                    .add_proxy(proxy.clone())
                    .await
                    .map_err(|e| e.to_string())?;
            }

            // 重新启动所有访问者
            for visitor in &self.config.visitors {
                self.visitor_manager
                    .add_visitor(visitor.clone())
                    .await
                    .map_err(|e| e.to_string())?;
            }

            // 重新启动健康检查（start_health_checks 需要 &mut self，先取出列表）
            self.stop_health_checks().await;
            let proxies = self.config.proxies.clone();
            self.start_health_checks(&proxies).await;

            log::info!("config reloaded successfully");
        }
        Ok(())
    }
}

// 注意：Client 不实现 Clone——Connector::new 依赖配置构造 TLS 连接管理器，可能失败，
// 而 Clone 无法传播错误（旧实现里 unwrap 会 panic）。全仓库也没有克隆 Client 的需求。

#[cfg(test)]
mod tls_config_tests {
    use super::*;
    use rust_frp_config::{ClientConfig, TlsConfig};

    fn config_with_tls(tls: TlsConfig) -> ClientConfig {
        let mut c = ClientConfig::default();
        c.transport.tls = Some(tls);
        c
    }

    /// TLS 关闭 → 不建 TLS 配置
    #[test]
    fn test_tls_disabled_returns_none() {
        let cfg = config_with_tls(TlsConfig {
            enable: false,
            ..TlsConfig::default()
        });
        assert!(build_client_tls_config(&cfg).unwrap().is_none());
    }

    /// 配置了 trusted_ca_file → CA 验证模式
    #[test]
    fn test_tls_with_ca_file() {
        let cfg = config_with_tls(TlsConfig {
            enable: true,
            trusted_ca_file: Some("/nonexistent/ca.crt".to_string()),
            ..TlsConfig::default()
        });
        // CA 文件不存在时返回 Err（读文件失败），但绝不能静默退化为 insecure
        let r = build_client_tls_config(&cfg);
        assert!(r.is_err(), "missing CA file must not fall back to insecure");
    }

    /// skip_verify = true → 显式跳过（insecure）
    #[test]
    fn test_tls_skip_verify_explicit() {
        let cfg = config_with_tls(TlsConfig {
            enable: true,
            skip_verify: true,
            ..TlsConfig::default()
        });
        assert!(build_client_tls_config(&cfg).unwrap().is_some());
    }

    /// 默认（无 CA、skip_verify = false）→ fail-closed 拒绝启动
    #[test]
    fn test_tls_default_fail_closed() {
        let cfg = config_with_tls(TlsConfig {
            enable: true,
            ..TlsConfig::default()
        });
        let err = match build_client_tls_config(&cfg) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("default TLS config must be rejected (fail-closed)"),
        };
        assert!(
            err.contains("fail-closed") || err.contains("skip_verify"),
            "{}",
            err
        );
    }
}

#[cfg(test)]
mod client_manager_tests {
    use super::*;
    use rust_frp_config::{ClientConfig, ProxyConfig, VisitorConfig};

    fn proxy(name: &str, r#type: &str) -> ProxyConfig {
        ProxyConfig {
            name: name.to_string(),
            r#type: r#type.to_string(),
            ..ProxyConfig::default()
        }
    }

    fn visitor(name: &str) -> VisitorConfig {
        VisitorConfig {
            name: name.to_string(),
            r#type: "stcp".to_string(),
            bind_addr: "127.0.0.1".to_string(),
            bind_port: 0,
            ..VisitorConfig::default()
        }
    }

    // 注册为不支持的代理类型：只写入注册表、不启动本地监听，避免端口占用
    #[tokio::test]
    async fn test_proxy_manager_add_status_remove_clear() {
        use rust_frp_core::ProxyManager;
        let mgr = ClientProxyManager::new();

        mgr.add_proxy(proxy("web", "unsupported-for-test"))
            .await
            .unwrap();
        assert_eq!(
            mgr.get_proxy_status("web").await.unwrap(),
            Some("running".to_string())
        );
        assert_eq!(mgr.get_proxy_status("missing").await.unwrap(), None);

        mgr.remove_proxy("web").await.unwrap();
        assert_eq!(mgr.get_proxy_status("web").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_proxy_manager_clear() {
        use rust_frp_core::ProxyManager;
        let mgr = ClientProxyManager::new();
        mgr.add_proxy(proxy("a", "unsupported-for-test"))
            .await
            .unwrap();
        mgr.add_proxy(proxy("b", "unsupported-for-test"))
            .await
            .unwrap();
        mgr.clear().await;
        assert_eq!(mgr.get_proxy_status("a").await.unwrap(), None);
        assert_eq!(mgr.get_proxy_status("b").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_visitor_manager_add_remove_clear() {
        use rust_frp_core::VisitorManager;
        let mgr = ClientVisitorManager::new();

        mgr.add_visitor(visitor("v1")).await.unwrap();
        mgr.add_visitor(visitor("v2")).await.unwrap();
        assert_eq!(mgr.visitors.read().await.len(), 2);

        mgr.remove_visitor("v1").await.unwrap();
        assert_eq!(mgr.visitors.read().await.len(), 1);
        assert!(mgr.visitors.read().await.contains_key("v2"));

        mgr.clear().await;
        assert!(mgr.visitors.read().await.is_empty());
    }

    #[test]
    fn test_work_conn_port_of_default_and_override() {
        let mut cfg = ClientConfig {
            server_port: 7100,
            work_conn_port: None,
            ..ClientConfig::default()
        };
        assert_eq!(work_conn_port_of(&cfg), 8100);

        cfg.work_conn_port = Some(7400);
        assert_eq!(work_conn_port_of(&cfg), 7400);
    }

    #[tokio::test]
    async fn test_health_checker_without_config_exits_immediately() {
        // 未配置 health_check 时检查任务应立即返回而不是空转
        let checker = HealthChecker::new(proxy("no-hc", "tcp"));
        let handle = checker.start();
        tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("health checker should exit immediately without health_check config")
            .unwrap();
    }

    #[tokio::test]
    async fn test_arc_config_sharing_is_cheap_and_consistent() {
        // 热路径共享 Arc<ClientConfig>：克隆是 O(1) 指针拷贝，指向同一份配置
        let cfg = ClientConfig {
            server_addr: "127.0.0.1".to_string(),
            server_port: 7000,
            ..ClientConfig::default()
        };
        let cfg = Arc::new(cfg);

        let shared = Arc::clone(&cfg);
        assert_eq!(shared.server_addr, cfg.server_addr);
        assert_eq!(shared.server_port, cfg.server_port);
        assert_eq!(Arc::strong_count(&cfg), 2);
    }
}

#[cfg(test)]
mod web_admin_tests {
    use super::*;
    use axum::body::Body;
    use std::time::Duration;
    use tower::ServiceExt;

    fn test_state() -> Arc<WebServerState> {
        Arc::new(WebServerState {
            proxy_manager: Arc::new(ClientProxyManager::new()),
            visitor_manager: Arc::new(ClientVisitorManager::new()),
            reload_notify: Arc::new(tokio::sync::Notify::new()),
            config_path: None,
            auth_enabled: false,
        })
    }

    fn temp_config_path(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        dir.join(format!(
            "frpc_admin_test_{tag}_{}",
            rust_frp_util::rand_id(8)
        ))
    }

    fn app_with_auth(auth: Option<(String, String)>) -> Router {
        let state = test_state();
        Router::new()
            .route("/status", get(status_handler))
            .route("/reload", post(reload_handler))
            .with_state(state)
            .layer(middleware::from_fn(move |req, next| {
                let auth = auth.clone();
                basic_auth_middleware(req, next, auth)
            }))
    }

    fn auth_header(user: &str, pass: &str) -> String {
        format!("Basic {}", base64::encode(format!("{user}:{pass}")))
    }

    #[tokio::test]
    async fn test_admin_api_open_when_no_auth_configured() {
        let app = app_with_auth(None);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn test_admin_api_rejects_missing_or_wrong_credentials() {
        let app = app_with_auth(Some(("admin".into(), "secret".into())));

        // 无凭据 → 401
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);

        // 密码错误 → 401
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .header(header::AUTHORIZATION, auth_header("admin", "wrong"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);

        // 用户名错误 → 401
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .header(header::AUTHORIZATION, auth_header("nope", "secret"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn test_admin_api_accepts_correct_credentials() {
        let app = app_with_auth(Some(("admin".into(), "secret".into())));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .header(header::AUTHORIZATION, auth_header("admin", "secret"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn test_reload_handler_signals_waiter() {
        let state = test_state();
        let notify = state.reload_notify.clone();
        let app = Router::new()
            .route("/reload", post(reload_handler))
            .with_state(state);

        let waiter = tokio::spawn(async move { notify.notified().await });
        tokio::task::yield_now().await;

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/reload")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("reload notify should reach the waiter")
            .unwrap();
    }

    #[tokio::test]
    async fn test_status_handler_lists_proxies_and_visitors() {
        let mut mgr = ClientProxyManager::new();
        mgr.set_work_conn_manager(Arc::new(WorkConnManager::new()));
        let state = Arc::new(WebServerState {
            proxy_manager: Arc::new(mgr),
            visitor_manager: Arc::new(ClientVisitorManager::new()),
            reload_notify: Arc::new(tokio::sync::Notify::new()),
            config_path: None,
            auth_enabled: false,
        });
        state
            .proxy_manager
            .add_proxy(rust_frp_config::ProxyConfig {
                name: "ssh".to_string(),
                r#type: "tcp".to_string(),
                local_ip: "127.0.0.1".to_string(),
                local_port: 0,
                remote_port: Some(6000),
                ..Default::default()
            })
            .await
            .unwrap();
        // 记录一次流量，验证 /status 暴露的累计字节数
        state.proxy_manager.record_traffic("ssh", 123, 456).await;

        let app = Router::new()
            .route("/status", get(status_handler))
            .with_state(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["proxies"][0]["name"], "ssh");
        assert_eq!(json["proxies"][0]["status"], "running");
        assert_eq!(json["proxies"][0]["remote_port"], 6000);
        assert_eq!(json["proxies"][0]["traffic_down"], 123);
        assert_eq!(json["proxies"][0]["traffic_up"], 456);
        assert_eq!(json["visitors"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_parse_basic_credentials() {
        let encoded = base64::encode("user:pass");
        assert_eq!(
            parse_basic_credentials(&format!("Basic {encoded}")),
            Some(("user".to_string(), "pass".to_string()))
        );
        assert_eq!(parse_basic_credentials("Bearer xyz"), None);
        assert_eq!(parse_basic_credentials("Basic !!!not-base64"), None);
        // 无冒号分隔的解码结果
        assert_eq!(
            parse_basic_credentials(&format!("Basic {}", base64::encode("nocolon"))),
            None
        );
    }
    fn config_app(state: Arc<WebServerState>, auth: Option<(String, String)>) -> Router {
        Router::new()
            .route("/config", get(get_config_handler).put(put_config_handler))
            .with_state(state)
            .layer(middleware::from_fn(move |req, next| {
                let auth = auth.clone();
                basic_auth_middleware(req, next, auth)
            }))
    }

    const VALID_CONFIG: &str = "server_addr = \"127.0.0.1\"\nserver_port = 9300\n\n[auth]\nmethod = \"token\"\ntoken = \"abc\"\n";

    #[tokio::test]
    async fn test_config_endpoints_forbidden_without_auth() {
        // 未配置 webServer user/password：GET/PUT /config 一律 403（fail-closed）
        let state = test_state();
        let app = config_app(state, None);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/config")
                    .body(Body::from("server_addr = \"x\""))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
    }

    fn state_with_config(
        path: &std::path::Path,
        notify: Arc<tokio::sync::Notify>,
    ) -> Arc<WebServerState> {
        Arc::new(WebServerState {
            proxy_manager: Arc::new(ClientProxyManager::new()),
            visitor_manager: Arc::new(ClientVisitorManager::new()),
            reload_notify: notify,
            config_path: Some(path.to_string_lossy().into_owned()),
            auth_enabled: true,
        })
    }

    #[tokio::test]
    async fn test_get_config_returns_file_content() {
        let path = temp_config_path("get");
        std::fs::write(&path, VALID_CONFIG).unwrap();

        let state = state_with_config(&path, Arc::new(tokio::sync::Notify::new()));
        let app = config_app(state, Some(("admin".into(), "secret".into())));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/config")
                    .header(header::AUTHORIZATION, auth_header("admin", "secret"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert_eq!(body, VALID_CONFIG);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_put_config_valid_writes_and_notifies() {
        let path = temp_config_path("put");
        std::fs::write(
            &path,
            "server_addr = \"old\"\nserver_port = 1\n[auth]\nmethod = \"token\"\ntoken = \"t\"\n",
        )
        .unwrap();

        let notify = Arc::new(tokio::sync::Notify::new());
        let state = state_with_config(&path, notify.clone());
        let app = config_app(state, Some(("admin".into(), "secret".into())));

        let waiter = tokio::spawn(async move { notify.notified().await });
        tokio::task::yield_now().await;

        let resp = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/config")
                    .header(header::AUTHORIZATION, auth_header("admin", "secret"))
                    .body(Body::from(VALID_CONFIG))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        // 文件已被原子覆写为新内容，且 reload 通知已发出
        let written = std::fs::read_to_string(&path).unwrap();
        assert_eq!(written, VALID_CONFIG);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("PUT /config should trigger reload notify")
            .unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_put_config_invalid_rejected_without_touching_file() {
        let path = temp_config_path("put_invalid");
        std::fs::write(&path, VALID_CONFIG).unwrap();

        let state = state_with_config(&path, Arc::new(tokio::sync::Notify::new()));
        let app = config_app(state, Some(("admin".into(), "secret".into())));

        // 缺 auth 段的非法配置 -> 400 且原文件不动
        let resp = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/config")
                    .header(header::AUTHORIZATION, auth_header("admin", "secret"))
                    .body(Body::from(
                        "server_addr = \"127.0.0.1\"\nserver_port = 99999\n",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), VALID_CONFIG);
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
mod sudp_tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    /// 测试用 FrpConn 适配器（内存双工流缺少 remote_addr，需包一层）
    struct TestConn(tokio::io::DuplexStream);

    impl AsyncRead for TestConn {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestConn {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl rust_frp_net::FrpConn for TestConn {
        fn remote_addr(&self) -> Option<SocketAddr> {
            None
        }
    }

    /// 本地 UDP 回声服务：回包带 `echo:` 前缀，便于区分会话
    async fn spawn_udp_echo() -> SocketAddr {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let mut reply = b"echo:".to_vec();
                reply.extend_from_slice(&buf[..n]);
                let _ = socket.send_to(&reply, peer).await;
            }
        });
        addr
    }

    /// 读取一条 UdpPacket 回包（心跳等控制消息跳过）
    async fn read_udp_reply(peer: &mut tokio::io::DuplexStream) -> rust_frp_core::UdpPacketMsg {
        loop {
            let received = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                rust_frp_core::read_message(peer),
            )
            .await
            .expect("reply timeout")
            .expect("reply read");
            match received {
                Message::UdpPacket(packet) => return packet,
                _ => continue,
            }
        }
    }

    /// 代理侧：隧道 UDP 包帧 → 本地 UDP 服务 → 回包按 client_addr 送回
    #[tokio::test]
    async fn test_sudp_proxy_forwards_and_isolates_sessions() {
        let local = spawn_udp_echo().await;
        let (tunnel, mut peer) = tokio::io::duplex(64 * 1024);

        tokio::spawn(serve_sudp_proxy(
            Box::new(TestConn(tunnel)),
            "sudp-test",
            local.to_string(),
        ));

        // 两个不同访问者源地址：回包必须回到各自的 client_addr
        for (client_addr, payload) in [("127.0.0.1:40001", "alpha"), ("127.0.0.1:40002", "beta")] {
            let msg = Message::UdpPacket(rust_frp_core::UdpPacketMsg {
                proxy_name: "sudp-test".to_string(),
                data: payload.as_bytes().to_vec(),
                client_addr: Some(client_addr.to_string()),
            });
            rust_frp_core::write_message(&mut peer, &msg).await.unwrap();

            let reply = read_udp_reply(&mut peer).await;
            assert_eq!(
                reply.client_addr.as_deref(),
                Some(client_addr),
                "回包应回到发起会话的访问者地址"
            );
            assert_eq!(
                String::from_utf8_lossy(&reply.data),
                format!("echo:{}", payload)
            );
        }
    }

    /// 隧道写任务按消息帧写入（读侧能还原同一条消息）
    #[tokio::test]
    async fn test_tunnel_writer_frames_messages() {
        let (tunnel, mut peer) = tokio::io::duplex(8 * 1024);
        let out_tx = spawn_tunnel_writer(TestConn(tunnel));

        let msg = Message::UdpPacket(rust_frp_core::UdpPacketMsg {
            proxy_name: "p".to_string(),
            data: vec![1, 2, 3],
            client_addr: Some("127.0.0.1:1".to_string()),
        });
        out_tx.send(msg).await.unwrap();

        match rust_frp_core::read_message(&mut peer).await.unwrap() {
            Message::UdpPacket(packet) => assert_eq!(packet.data, vec![1, 2, 3]),
            other => panic!("unexpected message: {other:?}"),
        }
    }
}

#[cfg(test)]
mod client_traffic_tests {
    use super::*;

    #[tokio::test]
    async fn test_manager_records_and_snapshots_traffic() {
        let mgr = ClientProxyManager::new();
        assert_eq!(mgr.traffic_snapshot("ssh").await, None);

        mgr.record_traffic("ssh", 100, 200).await;
        assert_eq!(mgr.traffic_snapshot("ssh").await, Some((100, 200)));

        // 累加语义，且不同代理互不影响
        mgr.record_traffic("ssh", 5, 6).await;
        mgr.record_traffic("web", 1, 2).await;
        assert_eq!(mgr.traffic_snapshot("ssh").await, Some((105, 206)));
        assert_eq!(mgr.traffic_snapshot("web").await, Some((1, 2)));
    }
}
