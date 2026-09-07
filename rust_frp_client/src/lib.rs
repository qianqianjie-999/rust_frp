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

use axum::{extract::State, routing::get, Json, Router};
use rust_frp_auth::AuthManager;
use rust_frp_config::ClientConfig;
use rust_frp_core::{ControlConn, Message, NewWorkConnMsg, ProxyManager, VisitorManager};
use rust_frp_net::{ConnManager, MuxSession, TlsConfig, TCP_MUX_MAGIC};
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
        }
    }

    pub fn set_work_conn_manager(&mut self, work_conn_manager: Arc<WorkConnManager>) {
        self.work_conn_manager = Some(work_conn_manager);
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
        let rate_bytes_per_sec = bandwidth_limit
            .as_deref()
            .and_then(rust_frp_util::parse_bandwidth_limit);

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
                                    Ok(n) => log::info!(
                                        "Server to local: {} bytes transferred (rate: {}B/s)",
                                        n,
                                        rate
                                    ),
                                    Err(e) => log::error!("Server to local error: {:?}", e),
                                }
                            };

                            let local_to_server = async {
                                match tokio::io::copy(
                                    &mut local_read,
                                    &mut rate_limited_server_write,
                                )
                                .await
                                {
                                    Ok(n) => log::info!(
                                        "Local to server: {} bytes transferred (rate: {}B/s)",
                                        n,
                                        rate
                                    ),
                                    Err(e) => log::error!("Local to server error: {:?}", e),
                                }
                            };

                            futures_util::future::join(server_to_local, local_to_server).await;
                        } else {
                            match rust_frp_util::bridge_streams(server_conn, local_conn).await {
                                Ok(_) => log::info!(
                                    "Bidirectional bridge completed for proxy: {}",
                                    proxy_name_clone
                                ),
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
            "tcp" | "http" | "https" | "websocket" => {
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
                self.start_work_conn_handler(
                    config.name.clone(),
                    local_addr,
                    rx,
                    config.bandwidth_limit.clone(),
                )
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
/// 与原版 frp 保持一致：
/// - 配置了 trusted_ca_file → 使用 CA 证书验证
/// - 未配置 trusted_ca_file → 跳过证书验证（默认行为）
fn build_client_tls_config(
    config: &rust_frp_config::ClientConfig,
) -> Result<Option<TlsConfig>, Box<dyn std::error::Error>> {
    Ok(if let Some(tls) = &config.transport.tls {
        if tls.enable {
            if let Some(ref ca_file) = tls.trusted_ca_file {
                Some(TlsConfig::new_client_with_ca_file(ca_file)?)
            } else {
                Some(TlsConfig::new_client_insecure()?)
            }
        } else {
            None
        }
    } else {
        None
    })
}

/// 计算服务器工作连接端口（frps.toml 的 work_conn_port，默认 server_port + 1000）
fn work_conn_port_of(config: &rust_frp_config::ClientConfig) -> u16 {
    config.work_conn_port.unwrap_or(config.server_port + 1000)
}

/// 客户端连接器
pub struct Connector {
    config: rust_frp_config::ClientConfig,
    conn_manager: ConnManager,
}

impl Connector {
    pub fn new(config: rust_frp_config::ClientConfig) -> Result<Self, Box<dyn std::error::Error>> {
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

/// 客户端控制
#[allow(dead_code)]
pub struct ClientControl {
    pub conn: ControlConn,
    run_id: String,
    proxy_manager: Arc<ClientProxyManager>,
    visitor_manager: Arc<ClientVisitorManager>,
    auth_manager: Arc<AuthManager>,
    work_conn_manager: Arc<WorkConnManager>,
    config: ClientConfig,
    udp_sockets: RwLock<std::collections::HashMap<String, Arc<tokio::net::UdpSocket>>>,
    udp_resp_tx: tokio::sync::mpsc::Sender<Message>,
    udp_resp_rx: tokio::sync::mpsc::Receiver<Message>,
    stcp_visitor_tx: tokio::sync::mpsc::Sender<Message>,
    stcp_visitor_rx: tokio::sync::mpsc::Receiver<Message>,
    last_pong_time: std::time::Instant,
    /// 工作连接是否使用 TLS（来自服务器 LoginRespMsg.work_conn_tls 协商）
    work_conn_tls: bool,
    /// yamux 多路复用会话（tcp_mux 开启时存在）
    ///
    /// 工作连接不再新建 TCP，而是从会话打开新流；
    /// TLS 在会话层（底层 TCP 已含），流上无需重复加密。
    mux_session: Option<Arc<MuxSession>>,
}

impl ClientControl {
    pub fn new(
        conn: ControlConn,
        run_id: String,
        proxy_manager: Arc<ClientProxyManager>,
        visitor_manager: Arc<ClientVisitorManager>,
        auth_manager: Arc<AuthManager>,
        work_conn_manager: Arc<WorkConnManager>,
        config: ClientConfig,
        work_conn_tls: bool,
        mux_session: Option<Arc<MuxSession>>,
    ) -> Self {
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
            work_conn_tls,
            mux_session,
        }
    }

    pub fn stcp_visitor_sender(&self) -> tokio::sync::mpsc::Sender<Message> {
        self.stcp_visitor_tx.clone()
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
                let config = self.config.clone();
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
                log::info!(
                    "Received XTCP NAT info from {} for proxy {}",
                    xtcp_msg.run_id,
                    xtcp_msg.proxy_name
                );
                let proxy_name = xtcp_msg.proxy_name.clone();
                let peer_local_addr = xtcp_msg.local_addr.clone();
                let peer_public_addr = xtcp_msg.public_addr.clone();

                // 如果本地有此 proxy 配置（即 proxy owner），回送自己的 NAT info
                if let Some(cfg) = self.config.proxies.iter().find(|p| p.name == proxy_name) {
                    let local_addr = format!("{}:{}", cfg.local_ip, cfg.local_port);
                    let nat_info = rust_frp_core::XtcpNatInfoMsg {
                        proxy_name: proxy_name.clone(),
                        run_id: self.run_id.clone(),
                        nat_type: "unknown".to_string(),
                        local_addr,
                        public_addr: String::new(),
                    };
                    if let Err(e) = self
                        .conn
                        .write_message(&Message::XtcpNatInfo(nat_info))
                        .await
                    {
                        log::error!("Failed to send XTCP NAT info response: {:?}", e);
                    }
                }

                // 尝试打洞
                tokio::spawn(async move {
                    try_xtcp_hole_punch(&proxy_name, &peer_public_addr, &peer_local_addr).await;
                });
            }
            Message::XtcpHolePunch(hp_msg) => {
                log::info!(
                    "Received XTCP hole punch from {} for proxy {}",
                    hp_msg.from_run_id,
                    hp_msg.proxy_name
                );
                let peer_local = hp_msg.peer_local_addr.clone();
                let peer_public = hp_msg.peer_public_addr.clone();

                tokio::spawn(async move {
                    let addrs = vec![peer_public, peer_local];
                    for addr in &addrs {
                        if addr.is_empty() {
                            continue;
                        }
                        log::info!("XTCP hole punch: trying to connect to {}", addr);
                        match tokio::net::TcpStream::connect(addr).await {
                            Ok(_conn) => {
                                log::info!("XTCP hole punch succeeded to {}", addr);
                                break;
                            }
                            Err(e) => {
                                log::debug!("XTCP hole punch failed to {}: {:?}", addr, e);
                            }
                        }
                    }
                });
            }
            _ => {
                log::warn!("unexpected message: {:?}", msg);
            }
        }
    }
}

/// 生成工作连接签名密钥（与服务端 AuthManager::generate_work_conn_sign_key 一致）
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
        let work_port = work_conn_port_of(config);
        let work_addr = format!("{}:{}", config.server_addr, work_port);

        let work_conn = tokio::net::TcpStream::connect(&work_addr).await?;
        log::info!("Connected to server work conn port: {}", work_addr);

        // 服务器协商要求 TLS 时，工作连接套 TLS（复用控制连接的客户端 TLS 配置）
        if work_conn_tls {
            let tls_config = build_client_tls_config(config)
                .map_err(|e| format!("failed to build client TLS config: {}", e))?
                .ok_or("server requires TLS work conn but client tls is disabled")?;
            let tls_stream = tls_config
                .connect(&config.server_addr, work_conn)
                .await
                .map_err(|e| format!("work conn TLS handshake failed: {}", e))?;
            log::info!("Work conn TLS established for proxy: {}", proxy_name);
            Box::new(tls_stream)
        } else {
            Box::new(work_conn)
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
        use_encryption: false,
        use_compression: false,
    };
    rust_frp_core::write_message(&mut work_conn, &Message::NewWorkConn(new_work_conn_msg)).await?;

    // 等待 StartWorkConn 响应
    let resp = rust_frp_core::read_message(&mut work_conn).await?;
    let (src_addr, src_port) = match resp {
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

/// XTCP 打洞尝试：同时向对端的公网和本地地址发起 TCP 连接
async fn try_xtcp_hole_punch(proxy_name: &str, peer_public_addr: &str, peer_local_addr: &str) {
    let addrs: Vec<&str> = vec![peer_public_addr, peer_local_addr]
        .into_iter()
        .filter(|a| !a.is_empty())
        .collect();

    if addrs.is_empty() {
        log::error!(
            "XTCP hole punch: no valid peer addresses for {}",
            proxy_name
        );
        return;
    }

    let mut handles = Vec::new();
    for addr in addrs {
        let addr = addr.to_string();
        let name = proxy_name.to_string();
        handles.push(tokio::spawn(async move {
            log::info!(
                "XTCP hole punch: trying to connect to {} for {}",
                addr,
                name
            );
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                tokio::net::TcpStream::connect(&addr),
            )
            .await
            {
                Ok(Ok(_conn)) => {
                    log::info!("XTCP hole punch succeeded to {} for {}", addr, name);
                    Some(addr)
                }
                Ok(Err(e)) => {
                    log::debug!("XTCP hole punch failed to {}: {:?}", addr, e);
                    None
                }
                Err(_) => {
                    log::debug!("XTCP hole punch timeout to {}", addr);
                    None
                }
            }
        }));
    }

    for handle in handles {
        let _ = handle.await;
    }
}

/// 启动 STCP/XTCP 访问者：监听本地端口，当有连接时创建到服务器的工作连接并桥接
async fn start_stcp_visitor(
    bind_addr: String,
    proxy_name: String,
    stcp_tx: tokio::sync::mpsc::Sender<Message>,
    run_id: String,
    config: ClientConfig,
    work_conn_tls: bool,
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
                let cfg = config.clone();
                let wct = work_conn_tls;
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_stcp_visitor_conn(local_conn, pn, tx, rid, cfg, wct).await
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
/// XTCP 先发送 XtcpNatInfo 尝试打洞，超时后回退 STCP 服务端中继
async fn handle_stcp_visitor_conn(
    local_conn: tokio::net::TcpStream,
    proxy_name: String,
    stcp_tx: tokio::sync::mpsc::Sender<Message>,
    run_id: String,
    config: ClientConfig,
    work_conn_tls: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let is_xtcp = config
        .visitors
        .iter()
        .any(|v| v.server_name == proxy_name && v.r#type == "xtcp");
    // 也可检查 proxies 中是否有 xtcp 类型

    if is_xtcp {
        let _timestamp = get_timestamp();
        let xtcp_msg = rust_frp_core::XtcpNatInfoMsg {
            proxy_name: proxy_name.clone(),
            run_id: run_id.clone(),
            nat_type: "unknown".to_string(),
            local_addr: String::new(),
            public_addr: String::new(),
        };

        if let Err(e) = stcp_tx.send(Message::XtcpNatInfo(xtcp_msg)).await {
            log::error!("Failed to send XTCP NAT info: {:?}", e);
        }

        log::info!(
            "XTCP visitor: waiting for hole punch (2s) before STCP fallback for {}",
            proxy_name
        );
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    let timestamp = get_timestamp();
    let sign_key = config
        .auth
        .token
        .as_ref()
        .map(|_| timestamp.to_string())
        .unwrap_or_default();

    let stcp_msg = rust_frp_core::StcpVisitorMsg {
        proxy_name: proxy_name.clone(),
        run_id: run_id.clone(),
        timestamp,
        sign_key,
    };

    if let Err(e) = stcp_tx.send(Message::StcpVisitor(stcp_msg)).await {
        return Err(format!("Failed to send StcpVisitor: {}", e).into());
    }

    // 工作连接端口与 TLS 协商（与 establish_work_connection 保持一致）
    let work_port = work_conn_port_of(&config);
    let work_addr = format!("{}:{}", config.server_addr, work_port);
    let tcp_conn = tokio::net::TcpStream::connect(&work_addr).await?;
    log::info!("STCP visitor work conn to: {}", work_addr);
    let mut work_conn: Box<dyn rust_frp_net::FrpConn> = if work_conn_tls {
        let tls_config = build_client_tls_config(&config)
            .map_err(|e| format!("failed to build client TLS config: {}", e))?
            .ok_or("server requires TLS work conn but client tls is disabled")?;
        let tls_stream = tls_config
            .connect(&config.server_addr, tcp_conn)
            .await
            .map_err(|e| format!("work conn TLS handshake failed: {}", e))?;
        Box::new(tls_stream)
    } else {
        Box::new(tcp_conn)
    };

    let work_sign_key = config
        .auth
        .token
        .as_ref()
        .map(|token| generate_work_conn_sign_key(token, &run_id))
        .unwrap_or_default();

    let new_work_conn_msg = NewWorkConnMsg {
        run_id: run_id.clone(),
        proxy_name: proxy_name.clone(),
        timestamp: get_timestamp(),
        sign_key: work_sign_key,
        use_encryption: false,
        use_compression: false,
    };
    rust_frp_core::write_message(&mut work_conn, &Message::NewWorkConn(new_work_conn_msg)).await?;

    let resp = rust_frp_core::read_message(&mut work_conn).await?;
    match resp {
        Message::StartWorkConn(start_msg) => {
            if !start_msg.error.is_empty() {
                return Err(format!("Server error: {}", start_msg.error).into());
            }
            log::info!("STCP visitor work conn established for {}", proxy_name);
        }
        _ => {
            return Err("Unexpected response from server".into());
        }
    }

    rust_frp_util::bridge_streams(work_conn, local_conn).await?;
    Ok(())
}

/// Web 服务器
pub struct WebServer {
    addr: SocketAddr,
    server: Option<tokio::task::JoinHandle<()>>,
}

/// Web 服务器共享状态
#[derive(Clone)]
struct WebServerState {
    proxy_manager: Arc<ClientProxyManager>,
    visitor_manager: Arc<ClientVisitorManager>,
}

impl WebServer {
    pub fn new(
        config: &rust_frp_config::WebServerConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let addr = format!("{}:{}", config.addr, config.port).parse::<SocketAddr>()?;
        Ok(Self { addr, server: None })
    }

    pub async fn start(&mut self, client: &Client) -> Result<(), Box<dyn std::error::Error>> {
        let state = Arc::new(WebServerState {
            proxy_manager: client.proxy_manager.clone(),
            visitor_manager: client.visitor_manager.clone(),
        });

        let app = Router::new()
            .route("/health", get(health_handler))
            .route("/proxies", get(proxies_handler))
            .route("/visitors", get(visitors_handler))
            .with_state(state);

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
    config: ClientConfig,
    control: Option<Mutex<ClientControl>>,
    proxy_manager: Arc<ClientProxyManager>,
    visitor_manager: Arc<ClientVisitorManager>,
    auth_manager: Arc<AuthManager>,
    work_conn_manager: Arc<WorkConnManager>,
    connector: Connector,
    web_server: Option<WebServer>,
    config_path: Option<String>,
    health_check_handles: Vec<tokio::task::JoinHandle<()>>,
}

impl Client {
    pub fn new(
        config: ClientConfig,
        config_path: Option<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let auth_manager = Arc::new(AuthManager::new(&config.auth).map_err(|e| e.to_string())?);

        // 先创建可变的 proxy_manager，设置 work_conn_manager，再包装成 Arc
        let mut proxy_manager_instance = ClientProxyManager::new();
        let work_conn_manager = Arc::new(WorkConnManager::new());
        proxy_manager_instance.set_work_conn_manager(work_conn_manager.clone());
        let proxy_manager = Arc::new(proxy_manager_instance);

        let visitor_manager = Arc::new(ClientVisitorManager::new());
        let connector = Connector::new(config.clone())?;

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

        // 重连配置：首次断线立即重连（0ms），失败后 1s 起步指数退避，封顶 30s
        let mut reconnect_delay_ms: u64 = 0;
        let max_reconnect_delay_ms: u64 = 30_000;

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
                        drop(control);
                        for visitor in &self.config.visitors {
                            if visitor.r#type == "stcp" || visitor.r#type == "xtcp" {
                                let bind_addr = format!("{}:{}", visitor.bind_addr, visitor.bind_port);
                                let proxy_name = visitor.server_name.clone();
                                let stcp_tx = stcp_tx.clone();
                                let cfg = self.config.clone();
                                let rid = run_id.clone();
                                tokio::spawn(async move {
                                    start_stcp_visitor(bind_addr, proxy_name, stcp_tx, rid, cfg, work_conn_tls).await;
                                });
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

            // 如果是正常关闭（通过信号），不再重连
            if self.control.is_none() {
                break;
            }

            // 重连逻辑：首次立即重连，之后指数退避 + jitter
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

        let (mut conn, mux_session): (
            ControlConn,
            Option<Arc<MuxSession>>,
        ) = match protocol {
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
                let mut tcp = tokio::net::TcpStream::connect(addr).await
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
            token: self.config.auth.token.clone().unwrap_or_default(),
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
                let run_id = login_resp_msg.run_id.clone();
                let work_conn_tls = login_resp_msg.work_conn_tls;
                if work_conn_tls {
                    log::info!("Server negotiated TLS for work connections");
                }
                let control = ClientControl::new(
                    conn,
                    login_resp_msg.run_id,
                    self.proxy_manager.clone(),
                    self.visitor_manager.clone(),
                    self.auth_manager.clone(),
                    self.work_conn_manager.clone(),
                    self.config.clone(),
                    work_conn_tls,
                    mux_session,
                );
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

    pub async fn reload_config(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(config_path) = &self.config_path {
            let new_config = rust_frp_config::ConfigLoader::load_client_config(config_path)?;
            self.config = new_config;

            // 重新启动所有代理
            let proxies = self.config.proxies.clone();
            for proxy in &proxies {
                self.proxy_manager
                    .add_proxy(proxy.clone())
                    .await
                    .map_err(|e| e.to_string())?;
            }

            // 重新启动所有访问者
            let visitors = self.config.visitors.clone();
            for visitor in &visitors {
                self.visitor_manager
                    .add_visitor(visitor.clone())
                    .await
                    .map_err(|e| e.to_string())?;
            }

            // 重新启动健康检查
            self.stop_health_checks().await;
            self.start_health_checks(&proxies).await;

            log::info!("config reloaded successfully");
        }
        Ok(())
    }
}

impl Clone for Client {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            control: None,
            proxy_manager: self.proxy_manager.clone(),
            visitor_manager: self.visitor_manager.clone(),
            auth_manager: self.auth_manager.clone(),
            work_conn_manager: self.work_conn_manager.clone(),
            connector: Connector::new(self.config.clone()).unwrap(),
            web_server: None,
            config_path: self.config_path.clone(),
            health_check_handles: Vec::new(),
        }
    }
}
