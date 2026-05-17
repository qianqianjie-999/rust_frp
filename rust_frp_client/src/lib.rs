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
//! 服务器                          客户端
//!   │                               │
//!   │--- ReqWorkConnMsg ----------->│
//!   │                               │
//!   │                        establish_work_connection()
//!   │                               │
//!   │                        连接工作端口 (server_port + 1000)
//!   │                               │
//!   │<---- NewWorkConnMsg ----------│
//!   │                               │
//!   │                               │
//! ```
//!
//! ## 安全性
//!
//! - TLS 加密连接（默认启用）
//! - HMAC 签名验证
//! - Token 认证
//! - 连接重试机制
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

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::io::AsyncWriteExt;
use axum::{Router, routing::get, Json, extract::State};
use rust_frp_config::ClientConfig;
use rust_frp_core::{ControlConn, Message, ProxyManager, VisitorManager, NewWorkConnMsg};
use rust_frp_net::{ConnManager, TlsConfig};
use rust_frp_auth::AuthManager;
use rust_frp_util::{get_timestamp, rand_id, retry::{RetryConfig, retry, ConnectionError}};

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

type WorkConnSenderMap = RwLock<std::collections::HashMap<String, mpsc::Sender<(tokio::net::TcpStream, Vec<u8>)>>>;

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

    pub async fn register_work_conn_handler(&self, proxy_name: String, sender: mpsc::Sender<(tokio::net::TcpStream, Vec<u8>)>) {
        let mut senders = self.work_conn_senders.write().await;
        senders.insert(proxy_name, sender);
    }

    pub async fn get_work_conn_sender(&self, proxy_name: &str) -> Option<mpsc::Sender<(tokio::net::TcpStream, Vec<u8>)>> {
        let senders = self.work_conn_senders.read().await;
        senders.get(proxy_name).cloned()
    }

    pub async fn handle_work_conn(&self, proxy_name: &str, server_conn: tokio::net::TcpStream, initial_data: Vec<u8>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
    ) {
        let proxy_name_clone = proxy_name.clone();
        let handle = tokio::spawn(async move {
            log::info!("Starting work connection handler for proxy: {}", proxy_name_clone);
            
            while let Some((mut server_conn, initial_data)) = receiver.recv().await {
                log::info!("Received work connection for proxy: {}", proxy_name_clone);
                
                // 使用重试机制连接到本地服务
                let retry_config = RetryConfig::fast();
                let connect_result = retry(
                    &retry_config,
                    &format!("connect to local service for proxy {}", proxy_name_clone),
                    || async {
                        tokio::net::TcpStream::connect(&local_addr).await.map_err(|e| {
                            log::warn!("Connection attempt failed: {:?}", e);
                            ConnectionError::from(e)
                        })
                    }
                ).await;
                
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
                        let (mut server_read, mut server_write) = server_conn.split();
                        let (mut local_read, mut local_write) = local_conn.split();
                        
                        // 从服务器到本地
                        let server_to_local = async {
                            match tokio::io::copy(&mut server_read, &mut local_write).await {
                                Ok(n) => log::info!("Server to local: {} bytes transferred", n),
                                Err(e) => log::error!("Server to local error: {:?}", e),
                            }
                        };
                        
                        // 从本地到服务器
                        let local_to_server = async {
                            match tokio::io::copy(&mut local_read, &mut server_write).await {
                                Ok(n) => log::info!("Local to server: {} bytes transferred", n),
                                Err(e) => log::error!("Local to server error: {:?}", e),
                            }
                        };
                        
                        // 同时运行两个方向的转发
                        tokio::select! {
                            _ = server_to_local => {},
                            _ = local_to_server => {},
                        }
                        
                        log::info!("Work connection closed for proxy: {}", proxy_name_clone);
                    }
                    Err(e) => {
                        log::error!("Failed to connect to local service at {:?} after retries: {:?}", local_addr, e);
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
            
            log::info!("Work connection handler stopped for proxy: {}", proxy_name_clone);
        });
        
        let mut handlers = self.work_conn_handlers.write().await;
        handlers.insert(proxy_name, handle);
    }

    pub async fn start_proxy(&self, config: &rust_frp_config::ProxyConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match config.r#type.as_str() {
            "tcp" => {
                let local_addr = format!("{}:{}", config.local_ip, config.local_port)
                    .parse::<SocketAddr>()?;
                log::info!("starting TCP proxy: {} -> {}", config.name, local_addr);
                
                // 为 TCP 代理创建工作连接通道
                // 当服务器收到外部连接时，会通过这个通道通知客户端
                let (tx, rx) = mpsc::channel::<(tokio::net::TcpStream, Vec<u8>)>(100);
                self.start_work_conn_handler(config.name.clone(), local_addr, rx).await;
                
                // 注册工作连接发送器到 WorkConnManager
                if let Some(work_conn_manager) = &self.work_conn_manager {
                    work_conn_manager.register_work_conn_handler(config.name.clone(), tx).await;
                } else {
                    log::error!("WorkConnManager not set for proxy: {}", config.name);
                    return Err("WorkConnManager not set".into());
                }
                
                Ok(())
            }
            "http" => {
                let local_addr = format!("{}:{}", config.local_ip, config.local_port)
                    .parse::<SocketAddr>()?;
                log::info!("starting HTTP proxy: {} -> {}", config.name, local_addr);
                
                // 为 HTTP 代理创建工作连接通道
                let (tx, rx) = mpsc::channel::<(tokio::net::TcpStream, Vec<u8>)>(100);
                self.start_work_conn_handler(config.name.clone(), local_addr, rx).await;
                
                // 注册工作连接发送器到 WorkConnManager
                if let Some(work_conn_manager) = &self.work_conn_manager {
                    work_conn_manager.register_work_conn_handler(config.name.clone(), tx).await;
                } else {
                    log::error!("WorkConnManager not set for proxy: {}", config.name);
                    return Err("WorkConnManager not set".into());
                }
                
                Ok(())
            }
            "https" => {
                let local_addr = format!("{}:{}", config.local_ip, config.local_port)
                    .parse::<SocketAddr>()?;
                log::info!("starting HTTPS proxy: {} -> {}", config.name, local_addr);
                
                // 为 HTTPS 代理创建工作连接通道
                let (tx, rx) = mpsc::channel::<(tokio::net::TcpStream, Vec<u8>)>(100);
                self.start_work_conn_handler(config.name.clone(), local_addr, rx).await;
                
                // 注册工作连接发送器到 WorkConnManager
                if let Some(work_conn_manager) = &self.work_conn_manager {
                    work_conn_manager.register_work_conn_handler(config.name.clone(), tx).await;
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

    pub async fn stop_proxy(&self, name: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
    async fn add_proxy(&self, config: rust_frp_config::ProxyConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut proxies = self.proxies.write().await;
        proxies.insert(config.name.clone(), config.clone());
        drop(proxies);
        let _ = self.start_proxy(&config).await?;
        Ok(())
    }

    async fn remove_proxy(&self, name: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.stop_proxy(name).await?;
        let mut proxies = self.proxies.write().await;
        proxies.remove(name);
        Ok(())
    }

    async fn get_proxy_status(&self, name: &str) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
        let proxies = self.proxies.read().await;
        if proxies.contains_key(name) {
            Ok(Some("running".to_string()))
        } else {
            Ok(None)
        }
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
    async fn add_visitor(&self, config: rust_frp_config::VisitorConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut visitors = self.visitors.write().await;
        visitors.insert(config.name.clone(), config);
        Ok(())
    }

    async fn remove_visitor(&self, name: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

/// 客户端连接器
pub struct Connector {
    config: rust_frp_config::ClientConfig,
    conn_manager: ConnManager,
}

impl Connector {
    pub fn new(config: rust_frp_config::ClientConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let tls_config = if let Some(tls) = &config.transport.tls {
            if tls.enable {
                Some(TlsConfig::new_client_trusting_builtin()?)
            } else {
                None
            }
        } else {
            None
        };

        let conn_manager = ConnManager::new(tls_config, config.transport.pool_count as usize);

        Ok(Self {
            config,
            conn_manager,
        })
    }

    pub async fn connect(&mut self) -> Result<rust_frp_net::PooledConn, Box<dyn std::error::Error>> {
        let addr = format!("{}:{}", self.config.server_addr, self.config.server_port)
            .parse::<SocketAddr>()?;
        Ok(self.conn_manager.connect_tcp(&addr).await?)
    }

    pub async fn connect_tls(&mut self, domain: &str) -> Result<tokio_openssl::SslStream<tokio::net::TcpStream>, Box<dyn std::error::Error>> {
        let addr = format!("{}:{}", self.config.server_addr, self.config.server_port)
            .parse::<SocketAddr>()?;
        Ok(self.conn_manager.connect_tls(domain, &addr).await?)
    }

    pub async fn connect_websocket(&mut self, url: &str) -> Result<rust_frp_net::WebSocketConn<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Box<dyn std::error::Error>> {
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
    ) -> Self {
        Self {
            conn,
            run_id,
            proxy_manager,
            visitor_manager,
            auth_manager,
            work_conn_manager,
            config,
        }
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut msg_count = 0u32;
        let _ping_interval: u32 = 10; // 每 10 个消息周期发送一次 ping
        let mut last_ping_time = std::time::Instant::now();
        
        log::debug!("ClientControl::run started, waiting for messages...");

        loop {
            // 定期发送 ping 消息（每 30 秒发送一次）
            if last_ping_time.elapsed() > std::time::Duration::from_secs(30) {
                let ping_msg = rust_frp_core::PingMsg {
                    timestamp: get_timestamp(),
                };
                log::debug!("Sending ping message, count: {}", msg_count);
                if let Err(e) = self.conn.write_message(&Message::Ping(ping_msg)).await {
                    log::error!("Failed to send ping: {:?}", e);
                    break;
                }
                last_ping_time = std::time::Instant::now();
            }

            log::debug!("Waiting for message, count: {}", msg_count);
            
            // 使用带超时的消息读取，避免永久阻塞
            let msg_result = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                self.conn.read_message()
            ).await;

            match msg_result {
                Ok(Ok(msg)) => {
                    msg_count += 1;
                    log::debug!("=== 成功读取消息 ===");
                    log::debug!("成功读取消息, 计数: {}", msg_count);
                    self.handle_message(msg).await;
                }
                Ok(Err(e)) => {
                    log::error!("=== 消息读取失败 ===");
                    log::error!("Failed to read message from connection: {:?}", e);
                    break;
                }
                Err(_) => {
                    log::warn!("消息读取超时，继续循环...");
                    // 超时后继续循环，不中断连接
                    continue;
                }
            }
        }

        Ok(())
    }

    /// 处理消息的通用方法
    async fn handle_message(&self, msg: Message) {
        match msg {
            Message::Pong(pong_msg) => {
                // 收到 pong 消息，继续循环
                log::debug!("收到 Pong 消息: timestamp={}", pong_msg.timestamp);
            }
            Message::ReqWorkConn(req_work_conn_msg) => {
                // 服务器请求建立工作连接
                log::debug!("收到 ReqWorkConn 消息: proxy={}", req_work_conn_msg.proxy_name);
                log::info!("Received ReqWorkConn for proxy: {}", req_work_conn_msg.proxy_name);
                let proxy_name = req_work_conn_msg.proxy_name.clone();
                let run_id = self.run_id.clone();
                let config = self.config.clone();

                tokio::spawn(async move {
                    log::debug!("开始建立工作连接: proxy={}", proxy_name);
                    if let Err(e) = establish_work_connection(
                        &proxy_name,
                        &run_id,
                        &config,
                    ).await {
                        if e.to_string().to_lowercase().contains("connection reset")
                            || e.to_string().to_lowercase().contains("connection aborted")
                            || e.to_string().to_lowercase().contains("broken pipe")
                        {
                            log::debug!("Work connection for {} closed (peer disconnected): {:?}", proxy_name, e);
                        } else {
                            log::error!("Failed to establish work connection for {}: {:?}", proxy_name, e);
                        }
                    } else {
                        log::debug!("工作连接建立成功: proxy={}", proxy_name);
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
    use ring::{hmac, digest};
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
async fn establish_work_connection(
    proxy_name: &str,
    run_id: &str,
    config: &ClientConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 查找代理配置
    let proxy_config = config.proxies.iter()
        .find(|p| p.name == proxy_name)
        .ok_or_else(|| format!("Proxy config not found: {}", proxy_name))?;

    // 连接到服务器的工作连接端口 (server_port + 1000)
    let work_port = config.server_port + 1000;
    let work_addr = format!("{}:{}", config.server_addr, work_port);

    let mut work_conn = tokio::net::TcpStream::connect(&work_addr).await?;
    log::info!("Connected to server work conn port: {}", work_addr);

    // 生成 sign_key
    let sign_key = config.auth.token.as_ref()
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
    match resp {
        Message::StartWorkConn(start_msg) => {
            if !start_msg.error.is_empty() {
                return Err(format!("Server error: {}", start_msg.error).into());
            }
            log::info!("Work conn established for proxy: {}", proxy_name);
        }
        _ => {
            return Err("Unexpected response from server".into());
        }
    }

    // 连接到本地服务
    let local_addr = format!("{}:{}", proxy_config.local_ip, proxy_config.local_port);
    let local_conn = tokio::net::TcpStream::connect(&local_addr).await?;
    log::info!("Connected to local service: {}", local_addr);

    // 双向桥接工作连接和本地连接
    rust_frp_util::bridge_connections(work_conn, local_conn).await?;
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
    pub fn new(config: &rust_frp_config::WebServerConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let addr = format!("{}:{}", config.addr, config.port).parse::<SocketAddr>()?;
        Ok(Self {
            addr,
            server: None,
        })
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
}

impl Client {
    pub fn new(config: ClientConfig, config_path: Option<String>) -> Result<Self, Box<dyn std::error::Error>> {
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
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

        // 重连配置
        let mut reconnect_delay_secs = 1u64;
        let max_reconnect_delay = 60u64;

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

            // 重连逻辑：指数退避
            log::warn!("Connection lost, attempting to reconnect in {} seconds...", reconnect_delay_secs);
            tokio::time::sleep(tokio::time::Duration::from_secs(reconnect_delay_secs)).await;
            
            // 增加延迟，但不超过最大值
            reconnect_delay_secs = (reconnect_delay_secs * 2).min(max_reconnect_delay);
            
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
            if let Err(e) = control.conn.write_message(&Message::Disconnect(disconnect_msg)).await {
                log::warn!("Failed to send disconnect message: {:?}", e);
            } else {
                log::info!("Disconnect message sent successfully");
            }
        }

        log::info!("Graceful shutdown completed");
        Ok(())
    }

    async fn register_proxy(&mut self, proxy: &rust_frp_config::ProxyConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(control) = &self.control {
            let mut control = control.lock().await;
            // 发送代理注册消息
            let register_proxy_msg = rust_frp_core::RegisterProxyMsg {
                proxy: proxy.clone(),
            };
            control.conn.write_message(&Message::RegisterProxy(register_proxy_msg)).await?;

            // 读取注册响应
            let msg = control.conn.read_message().await?;
            match msg {
                Message::RegisterProxyResp(resp) => {
                    if !resp.error.is_empty() {
                        return Err(Box::new(std::io::Error::other(
                            format!("Failed to register proxy {}: {}", proxy.name, resp.error),
                        )));
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
        // 连接到服务器
        let use_tls = self.config.transport.tls.as_ref().map(|t| t.enable).unwrap_or(true);
        
        let mut conn = if use_tls {
            let tls_conn = self.connector.connect_tls(&self.config.server_addr).await
                .map_err(|e| format!("TLS connection failed: {}", e))?;
            ControlConn::new(Box::new(tls_conn))
        } else {
            let tcp_conn = self.connector.connect().await
                .map_err(|e| format!("TCP connection failed: {}", e))?;
            ControlConn::new(Box::new(tcp_conn))
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

                // 创建客户端控制
                let run_id = login_resp_msg.run_id.clone();
                let control = ClientControl::new(
                    conn,
                    login_resp_msg.run_id,
                    self.proxy_manager.clone(),
                    self.visitor_manager.clone(),
                    self.auth_manager.clone(),
                    self.work_conn_manager.clone(),
                    self.config.clone(),
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

    pub async fn reload_config(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(config_path) = &self.config_path {
            let new_config = rust_frp_config::ConfigLoader::load_client_config(config_path)?;
            self.config = new_config;

            // 重新启动所有代理
            let proxies = self.config.proxies.clone();
            for proxy in &proxies {
                self.proxy_manager.add_proxy(proxy.clone()).await.map_err(|e| e.to_string())?;
            }

            // 重新启动所有访问者
            let visitors = self.config.visitors.clone();
            for visitor in &visitors {
                self.visitor_manager.add_visitor(visitor.clone()).await.map_err(|e| e.to_string())?;
            }

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
        }
    }
}
