use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::io::AsyncWriteExt;
use warp::Filter;
use rust_frp_config::ClientConfig;
use rust_frp_core::{ControlConn, Message, ProxyManager, VisitorManager, NewWorkConnMsg};
use rust_frp_net::{ConnManager, TlsConfig};
use rust_frp_auth::AuthManager;
use rust_frp_util::{get_timestamp, rand_id, retry::{RetryConfig, retry, ConnectionError}};

/// 工作连接管理器
pub struct WorkConnManager {
    // proxy_name -> sender for incoming connections (with initial data)
    work_conn_senders: RwLock<std::collections::HashMap<String, mpsc::Sender<(tokio::net::TcpStream, Vec<u8>)>>>,
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
}

impl ClientProxyManager {
    pub fn new() -> Self {
        Self {
            proxies: RwLock::new(std::collections::HashMap::new()),
            listeners: RwLock::new(std::collections::HashMap::new()),
            work_conn_handlers: RwLock::new(std::collections::HashMap::new()),
        }
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

    pub async fn start_proxy(&self, config: &rust_frp_config::ProxyConfig) -> Result<Option<mpsc::Sender<(tokio::net::TcpStream, Vec<u8>)>>, Box<dyn std::error::Error + Send + Sync>> {
        match config.r#type.as_str() {
            "tcp" => {
                let local_addr = format!("{}:{}", config.local_ip, config.local_port)
                    .parse::<SocketAddr>()?;
                log::info!("starting TCP proxy: {} -> {}", config.name, local_addr);
                
                // 启动本地监听器
                let listener = tokio::net::TcpListener::bind(&local_addr).await?;
                let proxy_name = config.name.clone();
                
                // 使用Arc来共享listener
                let listener_arc = std::sync::Arc::new(listener);
                let listener_clone = listener_arc.clone();
                
                tokio::spawn(async move {
                    loop {
                        match listener_clone.accept().await {
                            Ok((conn, _)) => {
                                log::info!("new local TCP connection for proxy: {}", proxy_name);
                                // 这里应该处理本地连接的转发
                                // 暂时关闭连接
                                drop(conn);
                            }
                            Err(e) => {
                                log::error!("accept local TCP connection error: {:?}", e);
                                break;
                            }
                        }
                    }
                });
                
                let mut listeners = self.listeners.write().await;
                listeners.insert(config.name.clone(), listener_arc);
                Ok(None)
            }
            "http" => {
                let local_addr = format!("{}:{}", config.local_ip, config.local_port)
                    .parse::<SocketAddr>()?;
                log::info!("starting HTTP proxy: {} -> {}", config.name, local_addr);
                
                // 为 HTTP 代理创建工作连接通道
                let (tx, rx) = mpsc::channel::<(tokio::net::TcpStream, Vec<u8>)>(100);
                self.start_work_conn_handler(config.name.clone(), local_addr, rx).await;
                
                // 返回发送器
                Ok(Some(tx))
            }
            "https" => {
                let local_addr = format!("{}:{}", config.local_ip, config.local_port)
                    .parse::<SocketAddr>()?;
                log::info!("starting HTTPS proxy: {} -> {}", config.name, local_addr);
                
                // 为 HTTPS 代理创建工作连接通道
                let (tx, rx) = mpsc::channel::<(tokio::net::TcpStream, Vec<u8>)>(100);
                self.start_work_conn_handler(config.name.clone(), local_addr, rx).await;
                
                // 返回发送器
                Ok(Some(tx))
            }
            _ => {
                log::warn!("unsupported proxy type: {}", config.r#type);
                Ok(None)
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
}

/// 客户端访问者管理器
pub struct ClientVisitorManager {
    visitors: RwLock<std::collections::HashMap<String, rust_frp_config::VisitorConfig>>,
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
                Some(TlsConfig::new_client()?)
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
        loop {
            // 发送 ping 消息
            let ping_msg = rust_frp_core::PingMsg {
                timestamp: get_timestamp(),
            };
            self.conn.write_message(&Message::Ping(ping_msg)).await?;

            // 读取响应
            match self.conn.read_message().await {
                Ok(msg) => {
                    match msg {
                        Message::Pong(_) => {
                            // 收到 pong 消息，继续循环
                        }
                        Message::StartWorkConn(start_work_conn_msg) => {
                            // 处理开始工作连接消息
                            if !start_work_conn_msg.error.is_empty() {
                                log::error!("start work conn error: {}", start_work_conn_msg.error);
                            } else {
                                log::info!("Received StartWorkConn, establishing work connection");
                                // 建立工作连接
                                if let Err(e) = self.establish_work_connection().await {
                                    log::error!("Failed to establish work connection: {:?}", e);
                                }
                            }
                        }
                        _ => {
                            log::warn!("unexpected message: {:?}", msg);
                        }
                    }
                }
                Err(e) => {
                    log::error!("read message error: {:?}", e);
                    break;
                }
            }

            // 等待一段时间后再次发送 ping
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        }
        Ok(())
    }

    async fn establish_work_connection(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 连接到服务器的工作端口
        let use_tls = self.config.transport.tls.as_ref().map(|t| t.enable).unwrap_or(false);
        let server_addr = format!("{}:{}", self.config.server_addr, self.config.server_port)
            .parse::<SocketAddr>()?;

        let mut work_conn = if use_tls {
            let tls_config = TlsConfig::new_client()?;
            let tcp_stream = tokio::net::TcpStream::connect(&server_addr).await?;
            let tls_stream = tls_config.connect(&self.config.server_addr, tcp_stream).await?;
            Box::new(tls_stream) as Box<dyn rust_frp_net::FrpConn>
        } else {
            let tcp_stream = tokio::net::TcpStream::connect(&server_addr).await?;
            Box::new(tcp_stream) as Box<dyn rust_frp_net::FrpConn>
        };

        // 发送 NewWorkConn 消息
        let new_work_conn_msg = NewWorkConnMsg {
            run_id: self.run_id.clone(),
            proxy_name: "".to_string(), // 会在后续确定
            timestamp: get_timestamp(),
            sign_key: self.auth_manager.generate_work_conn_sign_key(&self.run_id).await?,
            use_encryption: false,
            use_compression: false,
        };
        rust_frp_core::write_message(&mut work_conn, &Message::NewWorkConn(new_work_conn_msg)).await?;

        log::info!("Work connection established");
        
        // 这里应该将工作连接交给适当的代理处理
        // 暂时关闭连接
        drop(work_conn);
        
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

    pub async fn start(&mut self, client: &Client) -> Result<(), Box<dyn std::error::Error>> {
        let client1 = client.clone();
        let client2 = client.clone();

        // 健康检查
        let health = warp::path!("health").map(|| {
            warp::reply::json(&serde_json::json!({
                "status": "ok",
                "timestamp": get_timestamp(),
            }))
        });

        // 代理列表
        let proxies = warp::path!("proxies").and_then(move || {
            let client = client1.clone();
            async move {
                let proxies = client.proxy_manager.proxies.read().await;
                let proxy_list: Vec<rust_frp_config::ProxyConfig> = proxies.values().cloned().collect();
                Ok::<_, warp::Rejection>(warp::reply::json(&proxy_list))
            }
        });

        // 访问者列表
        let visitors = warp::path!("visitors").and_then(move || {
            let client = client2.clone();
            async move {
                let visitors = client.visitor_manager.visitors.read().await;
                let visitor_list: Vec<rust_frp_config::VisitorConfig> = visitors.values().cloned().collect();
                Ok::<_, warp::Rejection>(warp::reply::json(&visitor_list))
            }
        });

        let routes = health.or(proxies).or(visitors);
        let server = warp::serve(routes).bind(self.addr);
        let handle = tokio::spawn(server);
        self.server = Some(handle);

        Ok(())
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
}

impl Client {
    pub fn new(config: ClientConfig, config_path: Option<String>) -> Result<Self, Box<dyn std::error::Error>> {
        let auth_manager = Arc::new(AuthManager::new(&config.auth).map_err(|e| e.to_string())?);
        let proxy_manager = Arc::new(ClientProxyManager::new());
        let visitor_manager = Arc::new(ClientVisitorManager::new());
        let work_conn_manager = Arc::new(WorkConnManager::new());
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

        // 登录到服务器
        self.login().await.map_err(|e| e.to_string())?;

        // 克隆代理配置到临时向量
        let proxies = self.config.proxies.clone();
        
        log::info!("Number of proxies: {}", proxies.len());

        // 注册所有代理
        for proxy in &proxies {
            log::info!("Registering proxy: {}", proxy.name);
            self.register_proxy(proxy).await.map_err(|e| e.to_string())?;
        }

        // 启动所有代理
        for proxy in &proxies {
            log::info!("Starting proxy: {} on local port {}", proxy.name, proxy.local_port);
            self.proxy_manager.add_proxy(proxy.clone()).await.map_err(|e| e.to_string())?;
        }

        // 启动所有访问者
        for visitor in &self.config.visitors {
            self.visitor_manager.add_visitor(visitor.clone()).await.map_err(|e| e.to_string())?;
        }

        // 设置信号处理
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

        log::info!("Client started, waiting for signals...");

        // 运行控制循环，同时监听信号
        tokio::select! {
            _ = async {
                if let Some(control) = &self.control {
                    let mut control = control.lock().await;
                    control.run().await
                } else {
                    Ok(())
                }
            } => {
                log::info!("Control loop ended");
            }
            _ = sigint.recv() => {
                log::info!("Received SIGINT, shutting down gracefully...");
                self.graceful_shutdown().await?;
            }
            _ = sigterm.recv() => {
                log::info!("Received SIGTERM, shutting down gracefully...");
                self.graceful_shutdown().await?;
            }
        }

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
                        return Err(Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
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
        let use_tls = self.config.transport.tls.as_ref().map(|t| t.enable).unwrap_or(false);
        
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

        // 创建登录消息
        let login_msg = rust_frp_core::LoginMsg {
            arch: std::env::consts::ARCH.to_string(),
            os: std::env::consts::OS.to_string(),
            hostname: hostname::get()?.to_string_lossy().to_string(),
            pool_count: self.config.transport.pool_count,
            user: self.config.user.clone().unwrap_or_else(|| "".to_string()),
            client_id: self.config.client_id.clone().unwrap_or_else(|| "".to_string()),
            version: "0.1.0".to_string(),
            timestamp: get_timestamp(),
            run_id: run_id.clone(),
            token: self.config.auth.token.clone().unwrap_or_else(|| "".to_string()),
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
