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
//! 访问者        服务器                        客户端
//!   │              │                            │
//!   │--- TCP 请求 ->│                            │
//!   │              │ ReqWorkConnMsg ------------>│
//!   │              │                            │
//!   │              │              新建工作连接 ---│
//!   │              │<-------- NewWorkConn ------│
//!   │              │                            │
//!   │<--- 桥接 ---- │-------------------------->│
//!   │              │                            │
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

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Instant, Duration};
use tokio::sync::{RwLock, mpsc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use axum::extract::State;
use axum::response::IntoResponse;
use rust_frp_config::ServerConfig;
use rust_frp_core::{ControlConn, Message, ProxyManager, VisitorManager, NewWorkConnMsg};
use rust_frp_net::{TcpListener, UdpListener, TlsConfig, ConnManager};
use rust_frp_auth::AuthManager;
use rust_frp_util::get_timestamp;

/// 工作连接管理器
pub struct WorkConnManager {
    /// 等待工作连接的通道 (proxy_name, sender)
    pending_conns: RwLock<std::collections::HashMap<String, mpsc::Sender<tokio::net::TcpStream>>>,
}

impl WorkConnManager {
    pub fn new() -> Self {
        Self {
            pending_conns: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// 注册一个等待工作连接的请求
    pub async fn register_pending(&self, proxy_name: String) -> mpsc::Receiver<tokio::net::TcpStream> {
        let (tx, rx) = mpsc::channel::<tokio::net::TcpStream>(1);
        let mut pending = self.pending_conns.write().await;
        pending.insert(proxy_name, tx);
        rx
    }

    /// 完成一个工作连接
    pub async fn complete_work_conn(&self, proxy_name: &str, work_conn: tokio::net::TcpStream) -> Result<(), String> {
        let pending = self.pending_conns.read().await;
        if let Some(sender) = pending.get(proxy_name) {
            sender.send(work_conn).await.map_err(|e| format!("Failed to send work conn: {}", e))?;
            Ok(())
        } else {
            Err(format!("No pending work conn request for proxy: {}", proxy_name))
        }
    }

    /// 移除等待请求
    pub async fn remove_pending(&self, proxy_name: &str) {
        let mut pending = self.pending_conns.write().await;
        pending.remove(proxy_name);
    }
}

/// 等待的工作连接
pub struct PendingWorkConn {
    pub proxy_name: String,
    pub run_id: String,
    pub created_at: Instant,
    pub sender: tokio::sync::oneshot::Sender<Result<tokio::net::TcpStream, String>>,
}

/// 服务器工作连接管理器
pub struct ServerWorkConnManager {
    /// 等待工作连接的队列 (key -> pending request)
    pending: RwLock<std::collections::HashMap<String, PendingWorkConn>>,
    /// 请求计数器，用于生成唯一 key
    request_counter: std::sync::atomic::AtomicUsize,
}

impl ServerWorkConnManager {
    pub fn new() -> Self {
        Self {
            pending: RwLock::new(std::collections::HashMap::new()),
            request_counter: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// 生成唯一的请求 key
    pub fn generate_key(&self, proxy_name: &str) -> String {
        let counter = self.request_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        format!("{}:{}", proxy_name, counter)
    }

    /// 注册一个工作连接请求
    pub async fn register_request(
        &self,
        key: String,
        proxy_name: String,
        run_id: String,
        sender: tokio::sync::oneshot::Sender<Result<tokio::net::TcpStream, String>>
    ) -> Result<(), String> {
        let pending = PendingWorkConn {
            proxy_name: proxy_name.clone(),
            run_id,
            created_at: Instant::now(),
            sender,
        };

        let mut map = self.pending.write().await;
        map.insert(key.clone(), pending);
        log::info!("Registered work conn request for proxy: {}, key: {}", proxy_name, key);
        Ok(())
    }

    /// 完成工作连接（通过 proxy_name 匹配）
    pub async fn complete_work_conn(
        &self,
        proxy_name: &str,
        run_id: &str,
        work_conn: tokio::net::TcpStream
    ) -> Result<(), String> {
        let mut map = self.pending.write().await;

        // 找到匹配 proxy_name 的 pending 请求
        let matched_key = map.iter()
            .find(|(_, pending)| pending.proxy_name == proxy_name)
            .map(|(key, _)| key.clone());

        if let Some(key) = matched_key {
            let pending = map.remove(&key).unwrap();

            if pending.run_id != run_id {
                return Err("Run ID mismatch".to_string());
            }

            // 检查是否超时（超过30秒）
            if pending.created_at.elapsed() > Duration::from_secs(30) {
                return Err("Work conn request timeout".to_string());
            }

            // 发送工作连接给等待者
            if pending.sender.send(Ok(work_conn)).is_err() {
                return Err("Failed to send work conn to waiter".to_string());
            }

            log::info!("Completed work conn for proxy: {}, key: {}", proxy_name, key);
            Ok(())
        } else {
            Err(format!("No pending work conn request for proxy: {}", proxy_name))
        }
    }
    
    /// 清理超时的请求
    pub async fn cleanup_expired(&self, timeout: Duration) {
        let mut map = self.pending.write().await;
        let now = Instant::now();
        
        let expired_keys: Vec<String> = map.iter()
            .filter(|(_, pending)| now.duration_since(pending.created_at) > timeout)
            .map(|(key, _)| key.clone())
            .collect();
        
        for key in expired_keys {
            if let Some(pending) = map.remove(&key) {
                log::warn!("Cleaning up expired work conn request for proxy: {}", key);
                // 发送超时错误
                let _ = pending.sender.send(Err("Work conn request timeout".to_string()));
            }
        }
    }
    
    /// 获取等待中的请求数量
    pub async fn pending_count(&self) -> usize {
        let map = self.pending.read().await;
        map.len()
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
        use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};
        use base64::encode;

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

impl HttpVhostRouter {
    pub fn new() -> Self {
        Self {
            domain_map: RwLock::new(std::collections::HashMap::new()),
            proxy_configs: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// 注册 HTTP 代理的域名映射
    pub async fn register_proxy(&self, proxy_name: String, domains: Vec<String>, config: rust_frp_config::ProxyConfig) {
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

/// 监控指标
pub struct MonitorMetrics {
    total_connections: AtomicUsize,
    current_connections: AtomicUsize,
    total_proxies: AtomicUsize,
    current_proxies: AtomicUsize,
    bytes_sent: AtomicUsize,
    bytes_received: AtomicUsize,
    start_time: Instant,
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
    /// 登录成功通知通道
    login_tx: Option<mpsc::Sender<String>>,
    /// 消息发送通道（用于发送给客户端）
    msg_tx: Option<mpsc::Sender<Message>>,
}

impl Control {
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
        login_tx: Option<mpsc::Sender<String>>,
        msg_tx: Option<mpsc::Sender<Message>>,
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
            login_tx,
            msg_tx,
        }
    }

    /// 发送消息到客户端（通过消息通道，供外部 visitor handler 调用）
    pub async fn send_msg(&self, msg: &Message) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(tx) = &self.msg_tx {
            tx.send(msg.clone()).await?;
            Ok(())
        } else {
            Err("Message channel not initialized".into())
        }
    }

    /// 清理该客户端注册的所有代理
    async fn cleanup_proxies(&self) {
        log::info!("Client disconnected, cleaning up {} proxies", self.registered_proxies.len());
        for proxy_name in &self.registered_proxies {
            log::info!("Removing proxy: {}", proxy_name);
            if let Err(e) = self.proxy_manager.remove_proxy(proxy_name).await {
                log::error!("Failed to remove proxy {}: {:?}", proxy_name, e);
            } else {
                log::info!("Removed proxy: {}", proxy_name);
            }
            // 清理代理所有权
            self.proxy_owners.write().await.remove(proxy_name);
        }
    }

    /// 写消息到客户端
    async fn write_msg(&mut self, msg: &Message) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.conn.write_message(msg).await
    }

    pub async fn run(&mut self, mut msg_rx: mpsc::Receiver<Message>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log::info!("Control::run started");
        // 读取登录消息
        let msg_result = self.conn.read_message().await;

        match msg_result {
            Ok(msg) => {
                match msg {
                    Message::Login(login_msg) => {
                        log::info!("Received login message from user: {}", login_msg.user);
                        // 验证登录
                        let verify_result = self.auth_manager.verify_login(&login_msg.user, &login_msg.token).await;
                        if let Err(e) = verify_result {
                            log::error!("Login verification failed: {:?}", e);
                            return Err(format!("{:?}", e).into());
                        }

                        // 更新控制器的信息
                        self.run_id = login_msg.run_id;
                        self.user = login_msg.user;
                        self.client_id = login_msg.client_id;

                        // 注册客户端信息到 ControlManager
                        self.control_manager.add_client(
                            self.client_id.clone(),
                            self.run_id.clone(),
                            self.user.clone()
                        ).await;

                        // 发送登录响应
                        let resp = rust_frp_core::LoginRespMsg {
                            version: "0.1.0".to_string(),
                            run_id: self.run_id.clone(),
                            error: "".to_string(),
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
                                // 读取客户端消息
                                msg_result = self.conn.read_message() => {
                                    match msg_result {
                                        Ok(msg) => {
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
                                                    let result = self.proxy_manager.add_proxy(proxy).await;

                                                    let error_msg = match result {
                                                        Ok(_) => {
                                                            self.registered_proxies.push(proxy_name.clone());
                                                            self.proxy_owners.write().await.insert(proxy_name.clone(), self.run_id.clone());
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
                                                _ => {
                                                    log::warn!("unexpected message in loop: {:?}", msg);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            log::warn!("Client connection closed unexpectedly: {:?}", e);
                                            self.cleanup_proxies().await;
                                            return Ok(());
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

impl ControlManager {
    pub fn new() -> Self {
        Self {
            msg_channels: RwLock::new(std::collections::HashMap::new()),
            clients: RwLock::new(std::collections::HashMap::new()),
        }
    }

    pub async fn add(&self, run_id: String, msg_tx: mpsc::Sender<Message>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut msg_channels = self.msg_channels.write().await;
        msg_channels.insert(run_id.clone(), msg_tx);
        Ok(())
    }

    pub async fn remove(&self, run_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
        clients.insert(run_id.clone(), ClientInfo {
            run_id,
            client_id,
            user,
            connected_at: now,
            last_heartbeat: now,
        });
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

/// 服务器代理管理器
pub struct ServerProxyManager {
    proxies: RwLock<std::collections::HashMap<String, rust_frp_config::ProxyConfig>>,
    listeners: Arc<RwLock<std::collections::HashMap<String, (std::sync::Arc<tokio::net::TcpListener>, std::sync::Arc<std::sync::atomic::AtomicBool>)>>>,
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
        // 范围匹配
        let start = range.start.unwrap_or(0);
        let end = range.end.unwrap_or(65535);
        if port >= start && port <= end {
            return true;
        }
    }
    false
}

impl ServerProxyManager {
    pub fn new(
        http_vhost_router: Arc<HttpVhostRouter>,
        proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
        control_manager: Arc<ControlManager>,
        work_conn_manager: Arc<ServerWorkConnManager>,
        auth_manager: Arc<AuthManager>,
        allow_ports: Vec<rust_frp_config::PortRange>,
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
            http_vhost_router,
            proxy_owners,
            control_manager,
            work_conn_manager,
            auth_manager,
            allow_ports,
        }
    }

    pub async fn start_proxy(&self, config: &rust_frp_config::ProxyConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match config.r#type.as_str() {
            "tcp" => {
                if let Some(remote_port) = config.remote_port {
                    // 检查端口是否在允许列表中（空列表 = 默认拒绝所有）
                    if !port_allowed(remote_port, &self.allow_ports) {
                        return Err(format!("Port {} is not in the allowed ports list", remote_port).into());
                    }
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

                    tokio::spawn(async move {
                        while running_clone.load(std::sync::atomic::Ordering::Relaxed) {
                            match listener_clone.accept().await {
                                Ok((visitor_conn, visitor_addr)) => {
                                    log::info!("new TCP connection for proxy {} from {}", proxy_name, visitor_addr);

                                    let proxy_name_clone = proxy_name.clone();
                                    let proxy_owners = proxy_owners.clone();
                                    let control_manager = control_manager.clone();
                                    let work_conn_manager = work_conn_manager.clone();
                                    let auth_manager = auth_manager.clone();
                                    let plugin_config = plugin_config.clone();

                                    tokio::spawn(async move {
                                        log::debug!("开始处理外部连接: proxy={}", proxy_name_clone);
                                        
                                        // 检查是否有插件配置（插件直接处理访问者连接，不需要工作连接）
                                        if let Some(ref pconf) = plugin_config {
                                            log::debug!("使用插件处理连接: proxy={}", proxy_name_clone);
                                            let plugin_mgr = rust_frp_plugin::PluginManager::new();
                                            match plugin_mgr.create_plugin(pconf) {
                                                Ok(mut plugin) => {
                                                    if let Err(e) = plugin.handle(Box::new(visitor_conn)).await {
                                                        log::error!("Plugin handle error for proxy {}: {:?}", proxy_name_clone, e);
                                                    }
                                                }
                                                Err(e) => {
                                                    log::error!("Failed to create plugin for proxy {}: {:?}", proxy_name_clone, e);
                                                }
                                            }
                                            return;
                                        }

                                        log::debug!("使用工作连接协议处理: proxy={}", proxy_name_clone);

                                        // 1. 查找代理对应的 run_id
                                        let run_id = {
                                            let owners = proxy_owners.read().await;
                                            owners.get(&proxy_name_clone).cloned()
                                        };

                                        log::debug!("查找代理所有者: proxy={}, found={}", proxy_name_clone, run_id.is_some());

                                        let run_id = match run_id {
                                            Some(id) => id,
                                            None => {
                                                log::error!("No owner found for proxy: {}", proxy_name_clone);
                                                let _ = visitor_conn.try_write(b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 30\r\n\r\nProxy not registered by any client");
                                                return;
                                            }
                                        };

                                        log::debug!("找到代理所有者: proxy={}, run_id={}", proxy_name_clone, run_id);

                                        // 2. 获取对应的消息通道
                                        let msg_tx = match control_manager.get_msg_tx(&run_id).await {
                                            Some(tx) => tx,
                                            None => {
                                                log::error!("Message channel not found for run_id: {}", run_id);
                                                let _ = visitor_conn.try_write(b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 37\r\n\r\nMessage channel not found");
                                                return;
                                            }
                                        };

                                        log::debug!("找到消息通道: proxy={}, run_id={}", proxy_name_clone, run_id);

                                        // 3. 创建 oneshot 通道用于接收工作连接
                                        let (tx, rx) = tokio::sync::oneshot::channel::<Result<tokio::net::TcpStream, String>>();

                                        // 4. 注册等待请求
                                        let key = work_conn_manager.generate_key(&proxy_name_clone);
                                        if let Err(e) = work_conn_manager.register_request(
                                            key.clone(),
                                            proxy_name_clone.clone(),
                                            run_id.clone(),
                                            tx,
                                        ).await {
                                            log::error!("Failed to register work conn request: {}", e);
                                            let _ = visitor_conn.try_write(b"HTTP/1.1 503 Service Unavailable\r\n\r\n");
                                            return;
                                        }

                                        // 5. 生成 sign_key 并发送 NewWorkConn 给客户端
                                        log::debug!("开始生成 sign_key: proxy={}, run_id={}", proxy_name_clone, run_id);
                                        let sign_key = match auth_manager.generate_work_conn_sign_key(&run_id).await {
                                            Ok(key) => {
                                                log::debug!("sign_key 生成成功: proxy={}, key_len={}", proxy_name_clone, key.len());
                                                key
                                            }
                                            Err(e) => {
                                                log::error!("Failed to generate sign_key: {:?}", e);
                                                String::new()
                                            }
                                        };
                                        log::debug!("准备创建 NewWorkConn 消息: proxy={}", proxy_name_clone);
                                        let _new_work_conn_msg = NewWorkConnMsg {
                                            run_id: run_id.clone(),
                                            proxy_name: proxy_name_clone.clone(),
                                            timestamp: get_timestamp(),
                                            sign_key,
                                            use_encryption: false,
                                            use_compression: false,
                                        };
                                        log::debug!("NewWorkConn 消息创建完成: proxy={}", proxy_name_clone);

                                        {
                                            // 发送 ReqWorkConn 消息，请求客户端建立工作连接
                                            log::debug!("发送 ReqWorkConn 消息到客户端: proxy={}", proxy_name_clone);

                                            let req_work_conn_msg = rust_frp_core::ReqWorkConnMsg {
                                                proxy_name: proxy_name_clone.clone(),
                                            };
                                            match msg_tx.send(Message::ReqWorkConn(req_work_conn_msg)).await {
                                                Ok(_) => {
                                                    log::debug!("=== ReqWorkConn 消息发送成功 (via channel) ===");
                                                }
                                                Err(e) => {
                                                    log::error!("=== ReqWorkConn 消息发送失败 ===");
                                                    log::error!("Failed to send ReqWorkConn to client: proxy={}, error={:?}", proxy_name_clone, e);
                                                    let _ = visitor_conn.try_write(b"HTTP/1.1 503 Service Unavailable\r\n\r\n");
                                                    return;
                                                }
                                            }
                                        }

                                        // 6. 等待工作连接（30秒超时）
                                        // 注意：这里等待的是客户端通过工作连接发送的 NewWorkConn 消息
                                        match tokio::time::timeout(Duration::from_secs(30), rx).await {
                                            Ok(Ok(Ok(work_conn))) => {
                                                log::info!("Got work conn for proxy {}, bridging with visitor", proxy_name_clone);
                                                // 7. 桥接访问者连接和工作连接
                                                if let Err(e) = rust_frp_util::bridge_connections(visitor_conn, work_conn).await {
                                                    log::error!("Bridge error for proxy {}: {:?}", proxy_name_clone, e);
                                                }
                                            }
                                            Ok(Ok(Err(e))) => {
                                                log::error!("Work conn error for proxy {}: {}", proxy_name_clone, e);
                                                let _ = visitor_conn.try_write(b"HTTP/1.1 503 Service Unavailable\r\n\r\n");
                                            }
                                            Ok(Err(_)) => {
                                                log::error!("Work conn channel closed for proxy {}", proxy_name_clone);
                                                let _ = visitor_conn.try_write(b"HTTP/1.1 503 Service Unavailable\r\n\r\n");
                                            }
                                            Err(_) => {
                                                log::error!("Timeout waiting for work conn for proxy {}", proxy_name_clone);
                                                let _ = visitor_conn.try_write(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n");
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

                    let mut listeners = listeners.write().await;
                    listeners.insert(config.name.clone(), (listener_arc, running));
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
                    self.http_vhost_router.register_proxy(config.name.clone(), domains, config.clone()).await;
                    log::info!("HTTP proxy {} registered with domains: {:?}", config.name, config.custom_domains);
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
                    self.http_vhost_router.register_proxy(config.name.clone(), domains, config.clone()).await;
                    log::info!("HTTPS proxy {} registered with domains: {:?}", config.name, config.custom_domains);
                }
            }
            _ => {
                log::warn!("unsupported proxy type: {}", config.r#type);
            }
        }
        Ok(())
    }

    pub async fn stop_proxy(&self, name: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log::info!("Stopping proxy: {}", name);
        
        // 从 HTTP 虚拟主机路由器中注销
        self.http_vhost_router.unregister_proxy(name).await;
        
        let mut listeners = self.listeners.write().await;
        log::info!("Listeners: {:?}", listeners);
        if let Some((_, running)) = listeners.remove(name) {
            // 设置running标志为false，停止任务
            running.store(false, std::sync::atomic::Ordering::Relaxed);
            // 等待一段时间，让任务有时间停止
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            log::info!("stopped proxy: {}", name);
        } else {
            log::info!("Proxy {} not found in listeners", name);
        }
        Ok(())
    }

    pub fn get_http_vhost_router(&self) -> Arc<HttpVhostRouter> {
        self.http_vhost_router.clone()
    }
}

#[async_trait::async_trait]
impl ProxyManager for ServerProxyManager {
    async fn add_proxy(&self, config: rust_frp_config::ProxyConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut proxies = self.proxies.write().await;
        proxies.insert(config.name.clone(), config.clone());
        drop(proxies);
        self.start_proxy(&config).await
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
        let mut proxies = self.proxies.write().await;
        proxies.clear();
        log::info!("Server proxy manager cleared");
    }
}

/// 服务器访问者管理器
pub struct ServerVisitorManager {
    visitors: RwLock<std::collections::HashMap<String, rust_frp_config::VisitorConfig>>,
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
        .route("/api/metrics", axum::routing::get(metrics_handler))
        .route("/api/controllers", axum::routing::get(controllers_handler))
        .route("/api/proxies", axum::routing::get(proxies_handler))
        .route("/", axum::routing::get(index_handler))
        .route("/index.html", axum::routing::get(index_handler))
        .route("/login", axum::routing::get(login_handler))
        .route("/login", axum::routing::post(login_post_handler))
        .route("/logout", axum::routing::get(logout_handler))
        .with_state(server);

    if user.is_some() && password.is_some() {
        log::info!("Web server authentication enabled");
        let web_user = user.clone().unwrap();
        let web_password = password.clone().unwrap();
        
        std::thread::spawn(move || {
            std::env::set_var("FRP_WEB_USER", web_user);
            std::env::set_var("FRP_WEB_PASSWORD", web_password);
        });
        
        let user = user.unwrap();
        let password = password.unwrap();
        app.layer(axum::middleware::from_fn(move |request: axum::extract::Request, next: axum::middleware::Next| {
            let user = user.clone();
            let password = password.clone();
            async move {
                let path = request.uri().path();
                
                if path == "/login" {
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
        }))
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

async fn metrics_handler(
    State(server): State<std::sync::Arc<Server>>,
) -> axum::Json<serde_json::Value> {
    let metrics = server.metrics.get_metrics();
    axum::Json(metrics)
}

async fn controllers_handler(
    State(server): State<std::sync::Arc<Server>>,
) -> axum::Json<Vec<serde_json::Value>> {
    let clients = server.control_manager.get_clients().await;
    let controller_list: Vec<serde_json::Value> = clients.into_iter().map(|client| {
        serde_json::json!({
            "user": client.user,
            "client_id": client.client_id,
            "run_id": client.run_id,
            "connected_at": client.connected_at.elapsed().as_secs(),
            "last_heartbeat": client.last_heartbeat.elapsed().as_secs(),
        })
    }).collect();
    axum::Json(controller_list)
}

async fn proxies_handler(
    State(server): State<std::sync::Arc<Server>>,
) -> axum::Json<Vec<serde_json::Value>> {
    let proxies = server.proxy_manager.proxies.read().await;
    let owners = server.proxy_manager.proxy_owners.read().await;
    let clients = server.control_manager.get_clients().await;
    let client_map: std::collections::HashMap<String, String> = clients.into_iter()
        .map(|c| (c.run_id, c.client_id))
        .collect();
    
    let proxy_list: Vec<serde_json::Value> = proxies.values().map(|proxy| {
        let client_id = owners.get(&proxy.name)
            .and_then(|run_id| client_map.get(run_id))
            .map(|s| s.clone())
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
    }).collect();
    axum::Json(proxy_list)
}

async fn index_handler() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("../web_ui.html"))
}

async fn login_handler() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("../login.html"))
}

async fn login_post_handler(
    body: String,
) -> impl axum::response::IntoResponse {
    let parts: Vec<(String, String)> = body
        .split('&')
        .filter_map(|s| {
            let mut parts = s.split('=');
            let key = parts.next()?.replace('+', " ");
            let value = parts.next()?.replace('+', " ");
            Some((key, urlencoding::decode(&value).unwrap_or_default().to_string()))
        })
        .collect();
    
    let username: String = parts.iter().find(|(k, _)| k == "username").map(|(_, v)| v.clone()).unwrap_or_default();
    let password: String = parts.iter().find(|(k, _)| k == "password").map(|(_, v)| v.clone()).unwrap_or_default();
    
    use std::sync::OnceLock;
    static USER: OnceLock<String> = OnceLock::new();
    static PASSWORD: OnceLock<String> = OnceLock::new();
    
    let config_user = USER.get_or_init(|| std::env::var("FRP_WEB_USER").unwrap_or_else(|_| "admin".to_string()));
    let config_password = PASSWORD.get_or_init(|| std::env::var("FRP_WEB_PASSWORD").unwrap_or_else(|_| "admin".to_string()));
    
    if username == *config_user && password == *config_password {
        let session = base64::encode(format!("{}:{}", config_user, config_password));
        axum::http::Response::builder()
            .status(axum::http::StatusCode::SEE_OTHER)
            .header("Location", "/")
            .header("Set-Cookie", format!("frp_session={}; HttpOnly; Path=/", session))
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

/// Web 服务器（基于 axum，支持 TLS）
pub struct WebServer {
    addr: SocketAddr,
    server: Option<tokio::task::JoinHandle<()>>,
    user: Option<String>,
    password: Option<String>,
    tls: Option<rust_frp_config::TlsConfig>,
}

impl WebServer {
    pub fn new(config: &rust_frp_config::WebServerConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let addr = format!("{}:{}", config.addr, config.port).parse::<SocketAddr>()?;
        Ok(Self {
            addr,
            server: None,
            user: config.user.clone(),
            password: config.password.clone(),
            tls: config.tls.clone(),
        })
    }

    pub async fn start(&mut self, server: &Server) -> Result<(), Box<dyn std::error::Error>> {
        let server = std::sync::Arc::new(server.clone());
        let user = self.user.clone();
        let password = self.password.clone();

        let app = create_routes(server, user, password);

        if let Some(tls_config) = &self.tls {
            if tls_config.enable {
                self.start_https(app).await?;
                return Ok(());
            }
        }

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

    async fn start_https(&mut self, _app: axum::Router) -> Result<(), Box<dyn std::error::Error>> {
        log::error!("HTTPS is not yet fully supported for axum web server");
        log::info!("Please use Nginx reverse proxy for HTTPS access");
        log::info!("Or set tls.enable = false to use HTTP only");
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
        Ok(Self { inner: std::sync::Arc::new(inner) })
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

    pub async fn accept(&self) -> Result<(tokio_openssl::SslStream<tokio::net::TcpStream>, SocketAddr), std::io::Error> {
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
}

impl Server {
    pub async fn new(config: ServerConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let auth_manager = Arc::new(AuthManager::new(&config.auth).map_err(|e| e.to_string())?);
        let control_manager = Arc::new(ControlManager::new());
        let http_vhost_router = Arc::new(HttpVhostRouter::new());
        let work_conn_manager = Arc::new(ServerWorkConnManager::new());
        let proxy_owners = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let proxy_manager = Arc::new(ServerProxyManager::new(
            http_vhost_router,
            proxy_owners.clone(),
            control_manager.clone(),
            work_conn_manager.clone(),
            auth_manager.clone(),
            config.allow_ports.clone(),
        ));
        let visitor_manager = Arc::new(ServerVisitorManager::new());
        let metrics = Arc::new(MonitorMetrics::new());

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
        let addr = format!("{}:{}", self.config.bind_addr, self.config.bind_port)
            .parse::<SocketAddr>()?;
        let tcp_listener = TcpListener::bind(&addr).await?;
        self.tcp_listener = Some(tcp_listener);
        log::info!("TCP listener started on {}", addr);

        // 启动 UDP 监听器（如果配置了 KCP 或 QUIC）
        if let Some(kcp_port) = self.config.kcp_bind_port {
            let addr = format!("{}:{}", self.config.bind_addr, kcp_port)
                .parse::<SocketAddr>()?;
            let udp_listener = UdpListener::bind(&addr).await?;
            self.udp_listener = Some(udp_listener);
            log::info!("UDP listener started on {}", addr);
        }

        // 启动 HTTP 虚拟主机监听器
        let vhost_http_port = self.config.vhost_http_port.unwrap_or(9090);
        log::info!("HTTP vhost listener started on {}", vhost_http_port);

        let addr = format!("{}:{}", self.config.bind_addr, vhost_http_port)
            .parse::<SocketAddr>()?;
        let vhost_listener = HttpVhostListener::bind(&addr).await?;
        self.vhost_http_listener = Some(vhost_listener);

        // 启动 HTTP 虚拟主机连接处理任务
        let http_vhost_router = self.proxy_manager.get_http_vhost_router();
        let vhost_listener = self.vhost_http_listener.as_ref().unwrap();
        let metrics = self.metrics.clone();
        self.start_http_vhost_handler(vhost_listener, http_vhost_router, metrics).await?;

        // 启动 HTTPS 虚拟主机监听器
        let tls_config = self.conn_manager.get_tls_config();
        if let Some(tls_cfg) = tls_config {
            let vhost_https_port = self.config.vhost_https_port.unwrap_or(9091);
            log::info!("HTTPS vhost listener started on {}", vhost_https_port);
            let addr = format!("{}:{}", self.config.bind_addr, vhost_https_port)
                .parse::<SocketAddr>()?;
            let vhost_listener = HttpsVhostListener::bind(&addr, tls_cfg.clone()).await?;
            self.vhost_https_listener = Some(vhost_listener);
            log::info!("HTTPS vhost listener started on {}", addr);

            // 启动 HTTPS 虚拟主机连接处理任务
            let http_vhost_router = self.proxy_manager.get_http_vhost_router();
            let vhost_listener = self.vhost_https_listener.as_ref().unwrap();
            let metrics = self.metrics.clone();
            self.start_https_vhost_handler(vhost_listener, http_vhost_router, metrics).await?;
        } else {
            log::warn!("No TLS config available, HTTPS vhost disabled");
        }

        // 启动工作连接监听器（如果配置了 work_conn_port）
        let work_conn_port = self.config.work_conn_port.unwrap_or(self.config.bind_port + 1000);
        let work_conn_addr = format!("{}:{}", self.config.bind_addr, work_conn_port)
            .parse::<SocketAddr>()?;
        let std_listener = std::net::TcpListener::bind(work_conn_addr)?;
        std_listener.set_nonblocking(true)?;
        let std_listener_clone = std_listener.try_clone()?;
        let work_conn_listener = tokio::net::TcpListener::from_std(std_listener)?;
        let work_conn_listener_clone = tokio::net::TcpListener::from_std(std_listener_clone)?;
        log::info!("Work connection listener started on {}", work_conn_addr);

        // 启动工作连接处理任务
        let control_manager = self.control_manager.clone();
        let work_conn_manager = self.work_conn_manager.clone();
        let auth_manager = self.auth_manager.clone();
        tokio::spawn(async move {
            Self::handle_work_connections(work_conn_listener_clone, control_manager, work_conn_manager, auth_manager).await;
        });

        self.work_conn_listener = Some(work_conn_listener);

        // 启动工作连接超时清理任务
        let wcm = self.work_conn_manager.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                wcm.cleanup_expired(Duration::from_secs(30)).await;
            }
        });

        // 开始处理连接
        self.handle_tcp_connections().await?;
        Ok(())
    }
    
    /// 处理工作连接
    async fn handle_work_connections(
        listener: tokio::net::TcpListener,
        control_manager: Arc<ControlManager>,
        work_conn_manager: Arc<ServerWorkConnManager>,
        auth_manager: Arc<AuthManager>,
    ) {
        log::info!("Work connection handler started");

        loop {
            match listener.accept().await {
                Ok((conn, addr)) => {
                    log::info!("New work connection from: {:?}", addr);

                    let cm = control_manager.clone();
                    let wcm = work_conn_manager.clone();
                    let am = auth_manager.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::process_work_conn(conn, cm, wcm, am).await {
                            log::error!("Failed to process work connection: {:?}", e);
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
        mut conn: tokio::net::TcpStream,
        control_manager: Arc<ControlManager>,
        work_conn_manager: Arc<ServerWorkConnManager>,
        auth_manager: Arc<AuthManager>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 读取客户端发送的 NewWorkConn 消息
        let msg = rust_frp_core::read_message(&mut conn).await?;

        match msg {
            Message::NewWorkConn(work_msg) => {
                log::info!("Work conn for proxy: {}, run_id: {}", work_msg.proxy_name, work_msg.run_id);

                // 验证 run_id 是否存在
                if control_manager.get_msg_tx(&work_msg.run_id).await.is_none() {
                    log::error!("Unknown run_id: {}", work_msg.run_id);
                    let resp = Message::StartWorkConn(rust_frp_core::StartWorkConnMsg {
                        error: "Unknown run_id".to_string(),
                    });
                    rust_frp_core::write_message(&mut conn, &resp).await?;
                    return Err("Unknown run_id".into());
                }

                // 验证 sign_key（如果服务器生成了 sign_key，客户端必须匹配）
                if !work_msg.sign_key.is_empty() {
                    match auth_manager.generate_work_conn_sign_key(&work_msg.run_id).await {
                        Ok(expected_key) => {
                            if work_msg.sign_key != expected_key {
                                log::error!("Sign key mismatch for proxy: {}", work_msg.proxy_name);
                                let resp = Message::StartWorkConn(rust_frp_core::StartWorkConnMsg {
                                    error: "Sign key verification failed".to_string(),
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

                // 先发送 StartWorkConn 成功响应
                let resp = Message::StartWorkConn(rust_frp_core::StartWorkConnMsg {
                    error: "".to_string(),
                });
                rust_frp_core::write_message(&mut conn, &resp).await?;

                // 将工作连接交付给等待的访问者处理器
                if let Err(e) = work_conn_manager.complete_work_conn(
                    &work_msg.proxy_name,
                    &work_msg.run_id,
                    conn,
                ).await {
                    log::error!("Failed to complete work conn: {}", e);
                    return Err(e.into());
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
                            if let Err(e) = Self::handle_http_vhost_connection(conn, router, po, cm, wcm, am).await {
                                log::error!("handle http vhost connection error: {:?}", e);
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
                                    if let Err(e) = Self::handle_https_vhost_connection(tls_conn, router, po, cm, wcm, am).await {
                                        log::error!("handle https vhost connection error: {:?}", e);
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

        log::info!("HTTP request: {} {} Host: {}", request_info.method, request_info.path, request_info.host);

        // 根据 Host 查找代理
        let proxy_name = match http_vhost_router.find_proxy_by_host(&request_info.host).await {
            Some(name) => name,
            None => {
                log::warn!("no proxy found for host: {}", request_info.host);
                let response = format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                    request_info.host.len() + 24,
                    format!("Proxy not found for host: {}", request_info.host)
                );
                conn.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };

        log::info!("routing HTTP request to proxy: {}", proxy_name);

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

        // 创建 oneshot 通道
        let (tx, rx) = tokio::sync::oneshot::channel::<Result<tokio::net::TcpStream, String>>();

        // 注册等待请求
        let key = work_conn_manager.generate_key(&proxy_name);
        if let Err(e) = work_conn_manager.register_request(
            key.clone(),
            proxy_name.clone(),
            run_id.clone(),
            tx,
        ).await {
            log::error!("Failed to register HTTP work conn request: {}", e);
            let response = "HTTP/1.1 503 Service Unavailable\r\n\r\n";
            conn.write_all(response.as_bytes()).await?;
            return Ok(());
        }

        // 发送 ReqWorkConn 消息，请求客户端建立工作连接
        {
            log::debug!("发送 ReqWorkConn 消息到客户端: proxy={}", proxy_name);

            let req_work_conn_msg = rust_frp_core::ReqWorkConnMsg {
                proxy_name: proxy_name.clone(),
            };
            match msg_tx.send(Message::ReqWorkConn(req_work_conn_msg)).await {
                Ok(_) => {
                    log::debug!("=== ReqWorkConn 消息发送成功 (via channel) ===");
                }
                Err(e) => {
                    log::error!("=== ReqWorkConn 消息发送失败 ===");
                    log::error!("Failed to send ReqWorkConn to client: proxy={}, error={:?}", proxy_name, e);
                    let response = "HTTP/1.1 503 Service Unavailable\r\n\r\n";
                    let _ = conn.write_all(response.as_bytes()).await;
                    return Ok(());
                }
            }
        }

        // 等待工作连接（30秒超时）
        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(Ok(mut work_conn))) => {
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
            Ok(Ok(Err(e))) => {
                log::error!("Work conn error for HTTP proxy {}: {}", proxy_name, e);
                let response = "HTTP/1.1 503 Service Unavailable\r\n\r\n";
                conn.write_all(response.as_bytes()).await?;
            }
            Ok(Err(_)) => {
                log::error!("Work conn channel closed for HTTP proxy {}", proxy_name);
                let response = "HTTP/1.1 503 Service Unavailable\r\n\r\n";
                conn.write_all(response.as_bytes()).await?;
            }
            Err(_) => {
                log::error!("Timeout waiting for work conn for HTTP proxy {}", proxy_name);
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

        log::info!("HTTPS request: {} {} Host: {}", request_info.method, request_info.path, request_info.host);

        // 根据 Host 查找代理
        let proxy_name = match http_vhost_router.find_proxy_by_host(&request_info.host).await {
            Some(name) => name,
            None => {
                log::warn!("no proxy found for host: {}", request_info.host);
                let response = format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                    request_info.host.len() + 24,
                    format!("Proxy not found for host: {}", request_info.host)
                );
                conn.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };

        log::info!("routing HTTPS request to proxy: {}", proxy_name);

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

        // 创建 oneshot 通道
        let (tx, rx) = tokio::sync::oneshot::channel::<Result<tokio::net::TcpStream, String>>();

        // 注册等待请求
        let key = work_conn_manager.generate_key(&proxy_name);
        if let Err(e) = work_conn_manager.register_request(
            key.clone(),
            proxy_name.clone(),
            run_id.clone(),
            tx,
        ).await {
            log::error!("Failed to register HTTPS work conn request: {}", e);
            let response = "HTTP/1.1 503 Service Unavailable\r\n\r\n";
            conn.write_all(response.as_bytes()).await?;
            return Ok(());
        }

        // 发送 ReqWorkConn 消息，请求客户端建立工作连接
        {
            log::debug!("发送 ReqWorkConn 消息到客户端: proxy={}", proxy_name);

            let req_work_conn_msg = rust_frp_core::ReqWorkConnMsg {
                proxy_name: proxy_name.clone(),
            };
            match msg_tx.send(Message::ReqWorkConn(req_work_conn_msg)).await {
                Ok(_) => {
                    log::debug!("=== ReqWorkConn 消息发送成功 (via channel) ===");
                }
                Err(e) => {
                    log::error!("=== ReqWorkConn 消息发送失败 ===");
                    log::error!("Failed to send ReqWorkConn to client: proxy={}, error={:?}", proxy_name, e);
                    let response = "HTTP/1.1 503 Service Unavailable\r\n\r\n";
                    conn.write_all(response.as_bytes()).await?;
                    return Ok(());
                }
            }
        }

        // 等待工作连接（30秒超时）
        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(Ok(work_conn))) => {
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
            Ok(Ok(Err(e))) => {
                log::error!("Work conn error for HTTPS proxy {}: {}", proxy_name, e);
                let response = "HTTP/1.1 503 Service Unavailable\r\n\r\n";
                conn.write_all(response.as_bytes()).await?;
            }
            Ok(Err(_)) => {
                log::error!("Work conn channel closed for HTTPS proxy {}", proxy_name);
                let response = "HTTP/1.1 503 Service Unavailable\r\n\r\n";
                conn.write_all(response.as_bytes()).await?;
            }
            Err(_) => {
                log::error!("Timeout waiting for work conn for HTTPS proxy {}", proxy_name);
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

    async fn handle_tcp_connections(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(listener) = &self.tcp_listener {
            let tls_config = if let Some(ref tls) = self.config.transport.tls {
                if tls.enable {
                    if let (Some(ref cert_file), Some(ref key_file)) = (&tls.cert_file, &tls.key_file) {
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
            loop {
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

                tokio::spawn(async move {
                    if let Err(e) = Self::handle_connection(
                        conn,
                        control_manager,
                        proxy_manager,
                        visitor_manager,
                        auth_manager,
                        proxy_owners,
                        tls_config,
                    ).await {
                        log::error!("handle connection error: {:?}", e);
                    }
                    metrics.decrement_connections();
                });
            }
        }
        Ok(())
    }

    async fn handle_connection(
        conn: tokio::net::TcpStream,
        control_manager: Arc<ControlManager>,
        proxy_manager: Arc<ServerProxyManager>,
        visitor_manager: Arc<ServerVisitorManager>,
        auth_manager: Arc<AuthManager>,
        proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
        tls_config: Option<TlsConfig>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let conn = if let Some(tls_config) = tls_config {
            // 处理 TLS 连接
            let tls_stream = tls_config.accept(conn).await
                .map_err(|e| format!("TLS accept failed: {}", e))?;
            ControlConn::new(Box::new(tls_stream))
        } else {
            // 处理普通 TCP 连接
            ControlConn::new(Box::new(conn))
        };

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
            Some(login_tx),
            Some(msg_tx),
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
        });

        Ok(())
    }
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
        }
    }
}
