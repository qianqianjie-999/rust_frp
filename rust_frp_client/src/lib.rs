use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use warp::Filter;
use rust_frp_config::ClientConfig;
use rust_frp_core::{ControlConn, Message, ProxyManager, VisitorManager};
use rust_frp_net::{ConnManager, TlsConfig};
use rust_frp_auth::AuthManager;
use rust_frp_util::{get_timestamp, rand_id};

/// 客户端代理管理器
pub struct ClientProxyManager {
    proxies: RwLock<std::collections::HashMap<String, rust_frp_config::ProxyConfig>>,
    listeners: RwLock<std::collections::HashMap<String, tokio::net::TcpListener>>,
}

impl ClientProxyManager {
    pub fn new() -> Self {
        Self {
            proxies: RwLock::new(std::collections::HashMap::new()),
            listeners: RwLock::new(std::collections::HashMap::new()),
        }
    }

    pub async fn start_proxy(&self, config: &rust_frp_config::ProxyConfig) -> Result<(), Box<dyn std::error::Error>> {
        match config.r#type.as_str() {
            "tcp" => {
                let local_addr = format!("{}:{}", config.local_ip, config.local_port)
                    .parse::<SocketAddr>()?;
                log::info!("starting TCP proxy: {} -> {}", config.name, local_addr);
            }
            "http" => {
                let local_addr = format!("{}:{}", config.local_ip, config.local_port)
                    .parse::<SocketAddr>()?;
                log::info!("starting HTTP proxy: {} -> {}", config.name, local_addr);
            }
            "https" => {
                let local_addr = format!("{}:{}", config.local_ip, config.local_port)
                    .parse::<SocketAddr>()?;
                log::info!("starting HTTPS proxy: {} -> {}", config.name, local_addr);
            }
            _ => {
                log::warn!("unsupported proxy type: {}", config.r#type);
            }
        }
        Ok(())
    }

    pub async fn stop_proxy(&self, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut listeners = self.listeners.write().await;
        if let Some(listener) = listeners.remove(name) {
            listener.shutdown().await?;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl ProxyManager for ClientProxyManager {
    async fn add_proxy(&self, config: rust_frp_config::ProxyConfig) -> Result<(), Box<dyn std::error::Error>> {
        let mut proxies = self.proxies.write().await;
        proxies.insert(config.name.clone(), config.clone());
        drop(proxies);
        self.start_proxy(&config).await
    }

    async fn remove_proxy(&self, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.stop_proxy(name).await?;
        let mut proxies = self.proxies.write().await;
        proxies.remove(name);
        Ok(())
    }

    async fn get_proxy_status(&self, name: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
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
    async fn add_visitor(&self, config: rust_frp_config::VisitorConfig) -> Result<(), Box<dyn std::error::Error>> {
        let mut visitors = self.visitors.write().await;
        visitors.insert(config.name.clone(), config);
        Ok(())
    }

    async fn remove_visitor(&self, name: &str) -> Result<(), Box<dyn std::error::Error>> {
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

    pub async fn connect(&mut self) -> Result<tokio::net::TcpStream, Box<dyn std::error::Error>> {
        let addr = format!("{}:{}", self.config.server_addr, self.config.server_port)
            .parse::<SocketAddr>()?;
        self.conn_manager.connect_tcp(&addr).await
    }

    pub async fn connect_tls(&mut self, domain: &str) -> Result<tokio_openssl::SslStream<tokio::net::TcpStream>, Box<dyn std::error::Error>> {
        let addr = format!("{}:{}", self.config.server_addr, self.config.server_port)
            .parse::<SocketAddr>()?;
        self.conn_manager.connect_tls(domain, &addr).await
    }

    pub async fn connect_websocket(&mut self, url: &str) -> Result<rust_frp_net::WebSocketConn, Box<dyn std::error::Error>> {
        self.conn_manager.connect_websocket(url).await
    }
}

/// 客户端控制
pub struct ClientControl {
    conn: ControlConn,
    run_id: String,
    proxy_manager: Arc<ClientProxyManager>,
    visitor_manager: Arc<ClientVisitorManager>,
    auth_manager: Arc<AuthManager>,
}

impl ClientControl {
    pub fn new(
        conn: ControlConn,
        run_id: String,
        proxy_manager: Arc<ClientProxyManager>,
        visitor_manager: Arc<ClientVisitorManager>,
        auth_manager: Arc<AuthManager>,
    ) -> Self {
        Self {
            conn,
            run_id,
            proxy_manager,
            visitor_manager,
            auth_manager,
        }
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
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
}

/// Web 服务器
pub struct WebServer {
    addr: SocketAddr,
    server: Option<warp::Server>,
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
        let client = client.clone();

        // 健康检查
        let health = warp::path!("health").map(|| {
            warp::reply::json(&serde_json::json!({
                "status": "ok",
                "timestamp": get_timestamp(),
            }))
        });

        // 代理列表
        let proxies = warp::path!("proxies").and_then(move || {
            let client = client.clone();
            async move {
                let proxies = client.proxy_manager.proxies.read().await;
                let proxy_list: Vec<rust_frp_config::ProxyConfig> = proxies.values().cloned().collect();
                Ok::<_, warp::Rejection>(warp::reply::json(&proxy_list))
            }
        });

        // 访问者列表
        let visitors = warp::path!("visitors").and_then(move || {
            let client = client.clone();
            async move {
                let visitors = client.visitor_manager.visitors.read().await;
                let visitor_list: Vec<rust_frp_config::VisitorConfig> = visitors.values().cloned().collect();
                Ok::<_, warp::Rejection>(warp::reply::json(&visitor_list))
            }
        });

        let routes = health.or(proxies).or(visitors);
        let server = warp::serve(routes).bind(self.addr);
        self.server = Some(server);

        tokio::spawn(async move {
            server.await;
        });

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
    connector: Connector,
    web_server: Option<WebServer>,
    config_path: Option<String>,
}

impl Client {
    pub fn new(config: ClientConfig, config_path: Option<String>) -> Result<Self, Box<dyn std::error::Error>> {
        let auth_manager = Arc::new(AuthManager::new(&config.auth)?);
        let proxy_manager = Arc::new(ClientProxyManager::new());
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
            connector,
            web_server,
            config_path,
        })
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // 启动 Web 服务器
        if let Some(web_server) = &mut self.web_server {
            web_server.start(self).await?;
            log::info!("web server started");
        }

        // 登录到服务器
        self.login().await?;

        // 启动所有代理
        for proxy in &self.config.proxies {
            self.proxy_manager.add_proxy(proxy.clone()).await?;
        }

        // 启动所有访问者
        for visitor in &self.config.visitors {
            self.visitor_manager.add_visitor(visitor.clone()).await?;
        }

        // 运行控制循环
        if let Some(control) = &self.control {
            let mut control = control.lock().await;
            control.run().await?;
        }

        Ok(())
    }

    async fn login(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // 连接到服务器
        let conn = self.connector.connect().await?;
        let mut conn = ControlConn::new(Box::new(conn));

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
                let control = ClientControl::new(
                    conn,
                    login_resp_msg.run_id,
                    self.proxy_manager.clone(),
                    self.visitor_manager.clone(),
                    self.auth_manager.clone(),
                );
                self.control = Some(Mutex::new(control));

                log::info!("login to server success, run_id: {}", login_resp_msg.run_id);
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
                self.proxy_manager.add_proxy(proxy.clone()).await?;
            }

            // 重新启动所有访问者
            let visitors = self.config.visitors.clone();
            for visitor in &visitors {
                self.visitor_manager.add_visitor(visitor.clone()).await?;
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
            connector: Connector::new(self.config.clone()).unwrap(),
            web_server: None,
            config_path: self.config_path.clone(),
        }
    }
}
