use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Instant, Duration};
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use warp::Filter;
use rust_frp_config::ServerConfig;
use rust_frp_core::{ControlConn, Message, ProxyManager, VisitorManager};
use rust_frp_net::{TcpListener, UdpListener, TlsConfig, ConnManager};
use rust_frp_auth::AuthManager;
use rust_frp_util::get_timestamp;

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
    // proxy_name -> (work_conn sender, pending connections)
    work_conn_senders: RwLock<std::collections::HashMap<String, mpsc::Sender<(tokio::net::TcpStream, Vec<u8>)>>>,
    // proxy_name -> proxy config
    proxy_configs: RwLock<std::collections::HashMap<String, rust_frp_config::ProxyConfig>>,
}

impl HttpVhostRouter {
    pub fn new() -> Self {
        Self {
            domain_map: RwLock::new(std::collections::HashMap::new()),
            work_conn_senders: RwLock::new(std::collections::HashMap::new()),
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
        
        let mut work_conn_senders = self.work_conn_senders.write().await;
        work_conn_senders.remove(proxy_name);
        
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

    /// 注册工作连接发送器
    pub async fn register_work_conn_sender(&self, proxy_name: String, sender: mpsc::Sender<(tokio::net::TcpStream, Vec<u8>)>) {
        let mut work_conn_senders = self.work_conn_senders.write().await;
        work_conn_senders.insert(proxy_name, sender);
    }

    /// 获取工作连接发送器
    pub async fn get_work_conn_sender(&self, proxy_name: &str) -> Option<mpsc::Sender<(tokio::net::TcpStream, Vec<u8>)>> {
        let work_conn_senders = self.work_conn_senders.read().await;
        work_conn_senders.get(proxy_name).cloned()
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
#[allow(dead_code)]
pub struct Control {
    conn: ControlConn,
    run_id: String,
    user: String,
    client_id: String,
    proxy_manager: Arc<dyn ProxyManager + Send + Sync>,
    visitor_manager: Arc<dyn VisitorManager + Send + Sync>,
    auth_manager: Arc<AuthManager>,
    last_heartbeat: Instant,
    registered_proxies: Vec<String>,
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
    ) -> Self {
        Self {
            conn,
            run_id,
            user,
            client_id,
            proxy_manager,
            visitor_manager,
            auth_manager,
            last_heartbeat: Instant::now(),
            registered_proxies: Vec::new(),
        }
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

                        // 发送登录响应
                        let resp = rust_frp_core::LoginRespMsg {
                            version: "0.1.0".to_string(),
                            run_id: self.run_id.clone(),
                            error: "".to_string(),
                        };
                        let write_result = self.conn.write_message(&Message::LoginResp(resp)).await;
                        if let Err(e) = write_result {
                            log::error!("Failed to send login response: {:?}", e);
                            // 清理该客户端注册的所有代理
                            log::info!("Client disconnected, cleaning up {} proxies", self.registered_proxies.len());
                            for proxy_name in &self.registered_proxies {
                                log::info!("Removing proxy: {}", proxy_name);
                                if let Err(e) = self.proxy_manager.remove_proxy(proxy_name).await {
                                    log::error!("Failed to remove proxy {}: {:?}", proxy_name, e);
                                } else {
                                    log::info!("Removed proxy: {}", proxy_name);
                                }
                            }
                            log::info!("Control::run finished");
                            return Err(e);
                        }
                        log::info!("Sent login response to user: {}", self.user);

                        // 等待客户端发送消息
                        loop {
                            match self.conn.read_message().await {
                                Ok(msg) => {
                                    match msg {
                                        Message::Ping(ping_msg) => {
                                            self.last_heartbeat = Instant::now();
                                            let pong_msg = rust_frp_core::PongMsg {
                                                timestamp: ping_msg.timestamp,
                                            };
                                            let write_result = self.conn.write_message(&Message::Pong(pong_msg)).await;
                                            if let Err(e) = write_result {
                                                log::error!("Failed to send pong message: {:?}", e);
                                                // 清理该客户端注册的所有代理
                                                log::info!("Client disconnected, cleaning up {} proxies", self.registered_proxies.len());
                                                for proxy_name in &self.registered_proxies {
                                                    log::info!("Removing proxy: {}", proxy_name);
                                                    if let Err(e) = self.proxy_manager.remove_proxy(proxy_name).await {
                                                        log::error!("Failed to remove proxy {}: {:?}", proxy_name, e);
                                                    } else {
                                                        log::info!("Removed proxy: {}", proxy_name);
                                                    }
                                                }
                                                log::info!("Control::run finished");
                                                return Err(e);
                                            }
                                        }
                                        Message::RegisterProxy(register_proxy_msg) => {
                                            // 注册代理
                                            let proxy = register_proxy_msg.proxy;
                                            let proxy_name = proxy.name.clone();
                                            let result = self.proxy_manager.add_proxy(proxy).await;
                                            
                                            let error_msg = match result {
                                                Ok(_) => {
                                                    // 将代理名称添加到注册列表
                                                    self.registered_proxies.push(proxy_name.clone());
                                                    "".to_string()
                                                },
                                                Err(e) => format!("{:?}", e),
                                            };
                                            
                                            let resp = rust_frp_core::RegisterProxyRespMsg {
                                                name: proxy_name.clone(),
                                                error: error_msg.clone(),
                                            };
                                            
                                            let write_result = self.conn.write_message(&Message::RegisterProxyResp(resp)).await;
                                            if let Err(e) = write_result {
                                                log::error!("Failed to send register proxy response: {:?}", e);
                                                // 清理该客户端注册的所有代理
                                                log::info!("Client disconnected, cleaning up {} proxies", self.registered_proxies.len());
                                                for proxy_name in &self.registered_proxies {
                                                    log::info!("Removing proxy: {}", proxy_name);
                                                    if let Err(e) = self.proxy_manager.remove_proxy(proxy_name).await {
                                                        log::error!("Failed to remove proxy {}: {:?}", proxy_name, e);
                                                    } else {
                                                        log::info!("Removed proxy: {}", proxy_name);
                                                    }
                                                }
                                                log::info!("Control::run finished");
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
                                            let write_result = self.conn.write_message(&Message::ProxyStatusResp(resp)).await;
                                            if let Err(e) = write_result {
                                                log::error!("Failed to send proxy status response: {:?}", e);
                                                // 清理该客户端注册的所有代理
                                                log::info!("Client disconnected, cleaning up {} proxies", self.registered_proxies.len());
                                                for proxy_name in &self.registered_proxies {
                                                    log::info!("Removing proxy: {}", proxy_name);
                                                    if let Err(e) = self.proxy_manager.remove_proxy(proxy_name).await {
                                                        log::error!("Failed to remove proxy {}: {:?}", proxy_name, e);
                                                    } else {
                                                        log::info!("Removed proxy: {}", proxy_name);
                                                    }
                                                }
                                                log::info!("Control::run finished");
                                                return Err(e);
                                            }
                                        }
                                        Message::NewWorkConn(new_work_conn_msg) => {
                                            // 验证工作连接
                                            let verify_result = self.auth_manager.verify_work_conn(&self.user, &new_work_conn_msg.sign_key).await;
                                            if let Err(e) = verify_result {
                                                log::error!("Work connection verification failed: {:?}", e);
                                                return Err(format!("{:?}", e).into());
                                            }
                                            // 发送开始工作连接消息
                                            let start_work_conn_msg = rust_frp_core::StartWorkConnMsg {
                                                error: "".to_string(),
                                            };
                                            let write_result = self.conn.write_message(&Message::StartWorkConn(start_work_conn_msg)).await;
                                            if let Err(e) = write_result {
                                                log::error!("Failed to send start work connection message: {:?}", e);
                                                // 清理该客户端注册的所有代理
                                                log::info!("Client disconnected, cleaning up {} proxies", self.registered_proxies.len());
                                                for proxy_name in &self.registered_proxies {
                                                    log::info!("Removing proxy: {}", proxy_name);
                                                    if let Err(e) = self.proxy_manager.remove_proxy(proxy_name).await {
                                                        log::error!("Failed to remove proxy {}: {:?}", proxy_name, e);
                                                    } else {
                                                        log::info!("Removed proxy: {}", proxy_name);
                                                    }
                                                }
                                                log::info!("Control::run finished");
                                                return Err(e);
                                            }
                                        }
                                        Message::Disconnect(disconnect_msg) => {
                                            log::info!("Received disconnect message from client: reason={}", disconnect_msg.reason);
                                            // 清理该客户端注册的所有代理
                                            log::info!("Client requested disconnect, cleaning up {} proxies", self.registered_proxies.len());
                                            for proxy_name in &self.registered_proxies {
                                                log::info!("Removing proxy: {}", proxy_name);
                                                if let Err(e) = self.proxy_manager.remove_proxy(proxy_name).await {
                                                    log::error!("Failed to remove proxy {}: {:?}", proxy_name, e);
                                                } else {
                                                    log::info!("Removed proxy: {}", proxy_name);
                                                }
                                            }
                                            log::info!("Control::run finished (graceful disconnect)");
                                            return Ok(());
                                        }
                                        _ => {
                                            log::warn!("unexpected message: {:?}", msg);
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::warn!("Client connection closed unexpectedly: {:?}", e);
                                    // 清理该客户端注册的所有代理
                                    log::info!("Client disconnected, cleaning up {} proxies", self.registered_proxies.len());
                                    for proxy_name in &self.registered_proxies {
                                        log::info!("Removing proxy: {}", proxy_name);
                                        if let Err(e) = self.proxy_manager.remove_proxy(proxy_name).await {
                                            log::error!("Failed to remove proxy {}: {:?}", proxy_name, e);
                                        } else {
                                            log::info!("Removed proxy: {}", proxy_name);
                                        }
                                    }
                                    log::info!("Control::run finished");
                                    break;
                                }
                            }
                        }
                    }
                    _ => {
                        log::warn!("unexpected message: {:?}", msg);
                        // 清理该客户端注册的所有代理
                        log::info!("Client disconnected, cleaning up {} proxies", self.registered_proxies.len());
                        for proxy_name in &self.registered_proxies {
                            log::info!("Removing proxy: {}", proxy_name);
                            if let Err(e) = self.proxy_manager.remove_proxy(proxy_name).await {
                                log::error!("Failed to remove proxy {}: {:?}", proxy_name, e);
                            } else {
                                log::info!("Removed proxy: {}", proxy_name);
                            }
                        }
                        log::info!("Control::run finished");
                        return Err("Unexpected message".into());
                    }
                }
            }
            Err(e) => {
                log::error!("read login message error: {:?}", e);
                // 清理该客户端注册的所有代理
                log::info!("Client disconnected, cleaning up {} proxies", self.registered_proxies.len());
                for proxy_name in &self.registered_proxies {
                    log::info!("Removing proxy: {}", proxy_name);
                    if let Err(e) = self.proxy_manager.remove_proxy(proxy_name).await {
                        log::error!("Failed to remove proxy {}: {:?}", proxy_name, e);
                    } else {
                        log::info!("Removed proxy: {}", proxy_name);
                    }
                }
                log::info!("Control::run finished");
                return Err(e);
            }
        }
        
        Ok(())
    }
}

/// 控制器管理器
pub struct ControlManager {
    controls: RwLock<std::collections::HashMap<String, Arc<Mutex<Control>>>>,
}

impl ControlManager {
    pub fn new() -> Self {
        Self {
            controls: RwLock::new(std::collections::HashMap::new()),
        }
    }

    pub async fn add(&self, run_id: String, control: Control) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut controls = self.controls.write().await;
        controls.insert(run_id, Arc::new(Mutex::new(control)));
        Ok(())
    }

    pub async fn remove(&self, run_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut controls = self.controls.write().await;
        controls.remove(run_id);
        Ok(())
    }

    pub async fn get(&self, run_id: &str) -> Option<Arc<Mutex<Control>>> {
        let controls = self.controls.read().await;
        controls.get(run_id).cloned()
    }
}

/// 服务器代理管理器
pub struct ServerProxyManager {
    proxies: RwLock<std::collections::HashMap<String, rust_frp_config::ProxyConfig>>,
    listeners: Arc<RwLock<std::collections::HashMap<String, (std::sync::Arc<tokio::net::TcpListener>, std::sync::Arc<std::sync::atomic::AtomicBool>)>>>,
    http_vhost_router: Arc<HttpVhostRouter>,
}

impl ServerProxyManager {
    pub fn new(http_vhost_router: Arc<HttpVhostRouter>) -> Self {
        Self {
            proxies: RwLock::new(std::collections::HashMap::new()),
            listeners: Arc::new(RwLock::new(std::collections::HashMap::new())),
            http_vhost_router,
        }
    }

    pub async fn start_proxy(&self, config: &rust_frp_config::ProxyConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match config.r#type.as_str() {
            "tcp" => {
                if let Some(remote_port) = config.remote_port {
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

                    tokio::spawn(async move {
                        while running_clone.load(std::sync::atomic::Ordering::Relaxed) {
                            // 使用非阻塞的方式接受连接
                            match listener_clone.accept().await {
                                Ok((conn, _)) => {
                                    log::info!("new TCP connection for proxy: {}", proxy_name);
                                    // 这里应该处理 TCP 连接的转发
                                    // 暂时关闭连接
                                    drop(conn);
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
}

/// Web 服务器
pub struct WebServer {
    addr: SocketAddr,
    server: Option<tokio::task::JoinHandle<()>>,
}

impl WebServer {
    pub fn new(config: &rust_frp_config::WebServerConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let addr = format!("{}:{}", config.addr, config.port).parse::<SocketAddr>()?;
        Ok(Self {
            addr,
            server: None,
        })
    }

    pub async fn start(&mut self, server: &Server) -> Result<(), Box<dyn std::error::Error>> {
        let server1 = server.clone();
        let server2 = server.clone();
        let server3 = server.clone();

        // 健康检查
        let health = warp::path!("health").map(|| {
            warp::reply::json(&serde_json::json!({
                "status": "ok",
                "timestamp": get_timestamp(),
            }))
        });

        // API 路由组
        let api = warp::path!("api").and(
            // 监控指标
            warp::path!("metrics").and_then(move || {
                let server = server1.clone();
                async move {
                    let metrics = server.metrics.get_metrics();
                    Ok::<_, warp::Rejection>(warp::reply::json(&metrics))
                }
            })
            .or(
                // 控制器列表
                warp::path!("controllers").and_then(move || {
                    let server = server2.clone();
                    async move {
                        let controls = server.control_manager.controls.read().await;
                        let mut controller_list = Vec::new();
                        for control in controls.values() {
                            let control = control.lock().await;
                            controller_list.push(serde_json::json!({
                                "user": control.user,
                                "client_id": control.client_id,
                                "run_id": control.run_id,
                                "last_heartbeat": control.last_heartbeat.elapsed().as_secs(),
                            }));
                        }
                        Ok::<_, warp::Rejection>(warp::reply::json(&controller_list))
                    }
                })
            )
            .or(
                // 代理列表
                warp::path!("proxies").and_then(move || {
                    let server = server3.clone();
                    async move {
                        let proxies = server.proxy_manager.proxies.read().await;
                        let proxy_list: Vec<serde_json::Value> = proxies.values().map(|proxy| {
                            serde_json::json!({
                                "name": proxy.name,
                                "type": proxy.r#type,
                                "local_port": proxy.local_port,
                                "remote_port": proxy.remote_port,
                                "plugin": proxy.plugin,
                            })
                        }).collect();
                        Ok::<_, warp::Rejection>(warp::reply::json(&proxy_list))
                    }
                })
            )
        );

        // Web 管理界面
        let web_ui = warp::path::end()
            .or(warp::path!("index.html"))
            .map(|_| {
                warp::reply::html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>frp Server Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1, h2 { color: #333; }
        .card { background-color: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 20px; margin: 20px 0; }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .metric-card { background-color: #f9f9f9; border-radius: 8px; padding: 15px; text-align: center; }
        .metric-value { font-size: 24px; font-weight: bold; color: #007bff; }
        .metric-label { font-size: 14px; color: #666; margin-top: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
    </style>
</head>
<body>
    <h1>frp Server Dashboard</h1>
    <div class="card">
        <h2>Server Status</h2>
        <div class="metrics">
            <div class="metric-card">
                <div class="metric-value" id="client-count">0</div>
                <div class="metric-label">Connected Clients</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" id="proxy-count">0</div>
                <div class="metric-label">Active Proxies</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" id="visitor-count">0</div>
                <div class="metric-label">Active Visitors</div>
            </div>
        </div>
    </div>
    <div class="card">
        <h2>Connected Clients</h2>
        <table id="clients-table">
            <thead>
                <tr>
                    <th>Client ID</th>
                    <th>Run ID</th>
                    <th>Connected At</th>
                    <th>Last Heartbeat</th>
                </tr>
            </thead>
            <tbody>
                <!-- Client data will be inserted here -->
            </tbody>
        </table>
    </div>
    <div class="card">
        <h2>Active Proxies</h2>
        <table id="proxies-table">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Local Address</th>
                    <th>Remote Address</th>
                    <th>Client</th>
                </tr>
            </thead>
            <tbody>
                <!-- Proxy data will be inserted here -->
            </tbody>
        </table>
    </div>
    <script>
        // 定期刷新数据
        setInterval(async () => {
            try {
                // 获取服务器状态
                const statusResponse = await fetch('/api/status');
                const status = await statusResponse.json();
                document.getElementById('client-count').textContent = status.client_count;
                document.getElementById('proxy-count').textContent = status.proxy_count;
                document.getElementById('visitor-count').textContent = status.visitor_count;

                // 获取客户端列表
                const clientsResponse = await fetch('/api/clients');
                const clients = await clientsResponse.json();
                const clientsTable = document.getElementById('clients-table').querySelector('tbody');
                clientsTable.innerHTML = '';
                clients.forEach(client => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${client.client_id}</td>
                        <td>${client.run_id}</td>
                        <td>${new Date(client.connected_at * 1000).toLocaleString()}</td>
                        <td>${new Date(client.last_heartbeat * 1000).toLocaleString()}</td>
                    `;
                    clientsTable.appendChild(row);
                });

                // 获取代理列表
                const proxiesResponse = await fetch('/api/proxies');
                const proxies = await proxiesResponse.json();
                const proxiesTable = document.getElementById('proxies-table').querySelector('tbody');
                proxiesTable.innerHTML = '';
                proxies.forEach(proxy => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${proxy.name}</td>
                        <td>${proxy.type}</td>
                        <td>${proxy.local_addr}</td>
                        <td>${proxy.remote_addr}</td>
                        <td>${proxy.client_id}</td>
                    `;
                    proxiesTable.appendChild(row);
                });
            } catch (error) {
                console.error('Error fetching data:', error);
            }
        }, 5000);
    </script>
</body>
</html>
"#)
            });

        let routes = health.or(api).or(web_ui);
        let server = warp::serve(routes).bind(self.addr);
        let handle = tokio::spawn(server);
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
    web_server: Option<WebServer>,
    metrics: Arc<MonitorMetrics>,
}

impl Server {
    pub async fn new(config: ServerConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let auth_manager = Arc::new(AuthManager::new(&config.auth).map_err(|e| e.to_string())?);
        let control_manager = Arc::new(ControlManager::new());
        let http_vhost_router = Arc::new(HttpVhostRouter::new());
        let proxy_manager = Arc::new(ServerProxyManager::new(http_vhost_router));
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
            web_server,
            metrics,
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

        // 启动 HTTP 虚拟主机监听器（如果配置了 vhost_http_port）
        if let Some(vhost_http_port) = self.config.vhost_http_port {
            let addr = format!("{}:{}", self.config.bind_addr, vhost_http_port)
                .parse::<SocketAddr>()?;
            let vhost_listener = HttpVhostListener::bind(&addr).await?;
            self.vhost_http_listener = Some(vhost_listener);
            log::info!("HTTP vhost listener started on {}", addr);
            
            // 启动 HTTP 虚拟主机连接处理任务
            let http_vhost_router = self.proxy_manager.get_http_vhost_router();
            let vhost_listener = self.vhost_http_listener.as_ref().unwrap();
            let metrics = self.metrics.clone();
            self.start_http_vhost_handler(vhost_listener, http_vhost_router, metrics).await?;
        }

        // 启动 HTTPS 虚拟主机监听器（如果配置了 vhost_https_port 和 TLS）
        if let Some(vhost_https_port) = self.config.vhost_https_port {
            if let Some(tls_config) = self.conn_manager.get_tls_config() {
                let addr = format!("{}:{}", self.config.bind_addr, vhost_https_port)
                    .parse::<SocketAddr>()?;
                let vhost_listener = HttpsVhostListener::bind(&addr, tls_config.clone()).await?;
                self.vhost_https_listener = Some(vhost_listener);
                log::info!("HTTPS vhost listener started on {}", addr);
                
                // 启动 HTTPS 虚拟主机连接处理任务
                let http_vhost_router = self.proxy_manager.get_http_vhost_router();
                let vhost_listener = self.vhost_https_listener.as_ref().unwrap();
                let metrics = self.metrics.clone();
                self.start_https_vhost_handler(vhost_listener, http_vhost_router, metrics).await?;
            } else {
                log::warn!("vhost_https_port configured but no TLS config available");
            }
        }

        // 开始处理连接
        self.handle_tcp_connections().await?;
        Ok(())
    }

    async fn start_http_vhost_handler(
        &self,
        listener: &HttpVhostListener,
        http_vhost_router: Arc<HttpVhostRouter>,
        metrics: Arc<MonitorMetrics>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener_arc = listener.get_listener();
        
        tokio::spawn(async move {
            loop {
                match listener_arc.accept().await {
                    Ok((conn, addr)) => {
                        log::info!("new HTTP vhost connection from: {:?}", addr);
                        metrics.increment_connections();
                        let router = http_vhost_router.clone();
                        let metrics_clone = metrics.clone();
                        
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_http_vhost_connection(conn, router).await {
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
        
        tokio::spawn(async move {
            loop {
                match listener_arc.accept().await {
                    Ok((conn, addr)) => {
                        log::info!("new HTTPS vhost connection from: {:?}", addr);
                        metrics.increment_connections();
                        let router = http_vhost_router.clone();
                        let tls_config = tls_config.clone();
                        let metrics_clone = metrics.clone();
                        
                        tokio::spawn(async move {
                            // 先进行 TLS 握手
                            match tls_config.accept(conn).await {
                                Ok(mut tls_conn) => {
                                    if let Err(e) = Self::handle_https_vhost_connection(&mut tls_conn, router).await {
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
        
        log::info!("routing request to proxy: {}", proxy_name);
        
        // 获取工作连接发送器
        let sender = match http_vhost_router.get_work_conn_sender(&proxy_name).await {
            Some(s) => s,
            None => {
                log::warn!("no work connection available for proxy: {}", proxy_name);
                let response = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 35\r\n\r\nNo work connection available for proxy";
                conn.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };
        
        // 发送连接和已读取的数据给工作连接处理器
        let data = buf[..n].to_vec();
        if let Err(e) = sender.send((conn, data)).await {
            log::error!("failed to send connection to work conn handler: {:?}", e);
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "failed to send connection to work conn handler",
            )));
        }
        
        Ok(())
    }

    async fn handle_https_vhost_connection<S>(
        conn: &mut S,
        http_vhost_router: Arc<HttpVhostRouter>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> 
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync,
    {
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
        
        // 获取工作连接发送器
        let _sender = match http_vhost_router.get_work_conn_sender(&proxy_name).await {
            Some(s) => s,
            None => {
                log::warn!("no work connection available for proxy: {}", proxy_name);
                let response = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 35\r\n\r\nNo work connection available for proxy";
                conn.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        };
        
        // 对于 HTTPS，我们需要将 TLS 连接包装后发送
        // 这里简化处理，直接发送原始数据
        // 实际实现中可能需要使用 TLS 透传或终止
        let _data = buf[..n].to_vec();
        
        // 创建一个虚拟的 TcpStream 来传递数据
        // 实际实现中应该使用更复杂的方式来处理 TLS 连接
        log::info!("HTTPS connection forwarded to proxy: {}", proxy_name);
        
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
                let metrics = self.metrics.clone();
                let tls_config = tls_config.clone();

                tokio::spawn(async move {
                    if let Err(e) = Self::handle_connection(
                        conn,
                        control_manager,
                        proxy_manager,
                        visitor_manager,
                        auth_manager,
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
        _control_manager: Arc<ControlManager>,
        proxy_manager: Arc<ServerProxyManager>,
        visitor_manager: Arc<ServerVisitorManager>,
        auth_manager: Arc<AuthManager>,
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

        // 创建控制器
        let control = Control::new(
            conn,
            "".to_string(), // 暂时使用空字符串，控制器会从登录消息中获取 run_id
            "".to_string(), // 暂时使用空字符串，控制器会从登录消息中获取 user
            "".to_string(), // 暂时使用空字符串，控制器会从登录消息中获取 client_id
            proxy_manager,
            visitor_manager,
            auth_manager,
        );

        // 启动控制器
        tokio::spawn(async move {
            let mut control = control;
            if let Err(e) = control.run().await {
                log::error!("control run error: {:?}", e);
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
            web_server: None,
            metrics: self.metrics.clone(),
        }
    }
}
