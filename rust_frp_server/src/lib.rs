use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Instant, Duration};
use tokio::sync::{Mutex, RwLock};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use warp::Filter;
use rust_frp_config::ServerConfig;
use rust_frp_core::{ControlConn, Message, ProxyManager, VisitorManager};
use rust_frp_net::{TcpListener, UdpListener, TlsConfig, ConnManager};
use rust_frp_auth::AuthManager;
use rust_frp_util::get_timestamp;

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
    visitor_manager: Arc<dyn VisitorManager + Send + Sync>,
    auth_manager: Arc<AuthManager>,
    last_heartbeat: Instant,
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
        }
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // 发送登录响应
        let resp = rust_frp_core::LoginRespMsg {
            version: "0.1.0".to_string(),
            run_id: self.run_id.clone(),
            error: "".to_string(),
        };
        self.conn.write_message(&Message::LoginResp(resp)).await?;

        loop {
            match self.conn.read_message().await {
                Ok(msg) => {
                    match msg {
                        Message::Ping(ping_msg) => {
                            self.last_heartbeat = Instant::now();
                            let pong_msg = rust_frp_core::PongMsg {
                                timestamp: ping_msg.timestamp,
                            };
                            self.conn.write_message(&Message::Pong(pong_msg)).await?;
                        }
                        Message::ProxyStatus(proxy_status_msg) => {
                            let status = self.proxy_manager.get_proxy_status(&proxy_status_msg.name).await?;
                            let resp = rust_frp_core::ProxyStatusRespMsg {
                                name: proxy_status_msg.name,
                                status: status.unwrap_or_else(|| "unknown".to_string()),
                                error: "".to_string(),
                            };
                            self.conn.write_message(&Message::ProxyStatusResp(resp)).await?;
                        }
                        Message::NewWorkConn(new_work_conn_msg) => {
                            // 验证工作连接
                            self.auth_manager.verify_work_conn(&self.user, &new_work_conn_msg.sign_key).await?;
                            // 发送开始工作连接消息
                            let start_work_conn_msg = rust_frp_core::StartWorkConnMsg {
                                error: "".to_string(),
                            };
                            self.conn.write_message(&Message::StartWorkConn(start_work_conn_msg)).await?;
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

    pub async fn add(&self, run_id: String, control: Control) -> Result<(), Box<dyn std::error::Error>> {
        let mut controls = self.controls.write().await;
        controls.insert(run_id, Arc::new(Mutex::new(control)));
        Ok(())
    }

    pub async fn remove(&self, run_id: &str) -> Result<(), Box<dyn std::error::Error>> {
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
    listeners: RwLock<std::collections::HashMap<String, tokio::net::TcpListener>>,
}

impl ServerProxyManager {
    pub fn new() -> Self {
        Self {
            proxies: RwLock::new(std::collections::HashMap::new()),
            listeners: RwLock::new(std::collections::HashMap::new()),
        }
    }

    pub async fn start_proxy(&self, config: &rust_frp_config::ProxyConfig) -> Result<(), Box<dyn std::error::Error>> {
        match config.r#type.as_str() {
            "tcp" => {
                if let Some(remote_port) = config.remote_port {
                    let addr = format!("0.0.0.0:{}", remote_port).parse::<SocketAddr>()?;
                    let listener = tokio::net::TcpListener::bind(&addr).await?;
                    let proxy_name = config.name.clone();
                    let listeners = self.listeners.clone();

                    tokio::spawn(async move {
                        loop {
                            match listener.accept().await {
                                Ok((conn, _)) => {
                                    // 这里应该处理 TCP 连接的转发
                                    log::info!("new TCP connection for proxy: {}", proxy_name);
                                    // 暂时关闭连接
                                    drop(conn);
                                }
                                Err(e) => {
                                    log::error!("accept TCP connection error: {:?}", e);
                                    break;
                                }
                            }
                        }
                    });

                    let mut listeners = listeners.write().await;
                    listeners.insert(config.name.clone(), listener);
                }
            }
            "http" => {
                // 这里应该处理 HTTP 代理
            }
            "https" => {
                // 这里应该处理 HTTPS 代理
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
impl ProxyManager for ServerProxyManager {
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

    pub async fn start(&mut self, server: &Server) -> Result<(), Box<dyn std::error::Error>> {
        let server = server.clone();

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
                let server = server.clone();
                async move {
                    let metrics = server.metrics.get_metrics();
                    Ok::<_, warp::Rejection>(warp::reply::json(&metrics))
                }
            })
            .or(
                // 控制器列表
                warp::path!("controllers").and_then(move || {
                    let server = server.clone();
                    async move {
                        let controls = server.control_manager.controls.read().await;
                        let controller_list: Vec<serde_json::Value> = controls.values().map(|control| {
                            let control = control.lock().await;
                            serde_json::json!({
                                "user": control.user,
                                "client_id": control.client_id,
                                "run_id": control.run_id,
                                "last_heartbeat": control.last_heartbeat.elapsed().as_secs(),
                            })
                        }).collect();
                        Ok::<_, warp::Rejection>(warp::reply::json(&controller_list))
                    }
                })
            )
            .or(
                // 代理列表
                warp::path!("proxies").and_then(move || {
                    let server = server.clone();
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
            .map(|| {
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
        th { background-color: #f2f2f2; font-weight: bold; }
        tr:hover { background-color: #f5f5f5; }
        .status-indicator { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 5px; }
        .status-online { background-color: #28a745; }
        .status-offline { background-color: #dc3545; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .uptime { font-size: 14px; color: #666; }
    </style>
</head>
<body>
    <div class="header">
        <h1>frp Server Dashboard</h1>
        <div class="uptime" id="uptime">Uptime: 0s</div>
    </div>
    
    <div class="card">
        <h2>Server Metrics</h2>
        <div class="metrics" id="metrics">
            <div class="metric-card">
                <div class="metric-value" id="connections">0</div>
                <div class="metric-label">Current Connections</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" id="proxies">0</div>
                <div class="metric-label">Current Proxies</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" id="controllers">0</div>
                <div class="metric-label">Active Controllers</div>
            </div>
            <div class="metric-card">
                <div class="metric-value" id="traffic">0 KB</div>
                <div class="metric-label">Total Traffic</div>
            </div>
        </div>
    </div>
    
    <div class="card">
        <h2>Controllers</h2>
        <table id="controllers">
            <thead>
                <tr><th>User</th><th>Client ID</th><th>Run ID</th><th>Last Heartbeat</th><th>Status</th></tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>
    
    <div class="card">
        <h2>Proxies</h2>
        <table id="proxies">
            <thead>
                <tr><th>Name</th><th>Type</th><th>Local Port</th><th>Remote Port</th><th>Plugin</th></tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>
    
    <script>
        // 加载指标
        async function loadMetrics() {
            try {
                const response = await fetch('/api/metrics');
                const data = await response.json();
                
                document.getElementById('uptime').textContent = `Uptime: ${data.uptime}s`;
                document.getElementById('connections').textContent = data.current_connections;
                document.getElementById('proxies').textContent = data.current_proxies;
                
                const traffic = (data.bytes_sent + data.bytes_received) / 1024;
                document.getElementById('traffic').textContent = `${traffic.toFixed(2)} KB`;
            } catch (error) {
                console.error('Error loading metrics:', error);
            }
        }
        
        // 加载控制器
        async function loadControllers() {
            try {
                const response = await fetch('/api/controllers');
                const data = await response.json();
                
                const tbody = document.querySelector('#controllers tbody');
                tbody.innerHTML = '';
                
                if (data.length === 0) {
                    const row = document.createElement('tr');
                    row.innerHTML = '<td colspan="5">No controllers connected</td>';
                    tbody.appendChild(row);
                } else {
                    document.getElementById('controllers').textContent = data.length;
                    data.forEach(controller => {
                        const row = document.createElement('tr');
                        const statusClass = controller.last_heartbeat < 60 ? 'status-online' : 'status-offline';
                        const statusText = controller.last_heartbeat < 60 ? 'Online' : 'Offline';
                        
                        row.innerHTML = `
                            <td>${controller.user}</td>
                            <td>${controller.client_id}</td>
                            <td>${controller.run_id}</td>
                            <td>${controller.last_heartbeat}s</td>
                            <td><span class="status-indicator ${statusClass}"></span>${statusText}</td>
                        `;
                        tbody.appendChild(row);
                    });
                }
            } catch (error) {
                console.error('Error loading controllers:', error);
            }
        }
        
        // 加载代理
        async function loadProxies() {
            try {
                const response = await fetch('/api/proxies');
                const data = await response.json();
                
                const tbody = document.querySelector('#proxies tbody');
                tbody.innerHTML = '';
                
                if (data.length === 0) {
                    const row = document.createElement('tr');
                    row.innerHTML = '<td colspan="5">No proxies configured</td>';
                    tbody.appendChild(row);
                } else {
                    data.forEach(proxy => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${proxy.name}</td>
                            <td>${proxy.type}</td>
                            <td>${proxy.local_port || '-'}</td>
                            <td>${proxy.remote_port || '-'}</td>
                            <td>${proxy.plugin || '-'}</td>
                        `;
                        tbody.appendChild(row);
                    });
                }
            } catch (error) {
                console.error('Error loading proxies:', error);
            }
        }
        
        // 初始加载
        loadMetrics();
        loadControllers();
        loadProxies();
        
        // 定时刷新
        setInterval(loadMetrics, 5000);
        setInterval(loadControllers, 5000);
        setInterval(loadProxies, 5000);
    </script>
</body>
</html>
"#
            });

        let routes = health.or(api).or(web_ui);
        let server = warp::serve(routes).bind(self.addr);
        self.server = Some(server);

        tokio::spawn(async move {
            server.await;
        });

        Ok(())
    }
}

/// 服务器服务
pub struct Server {
    config: ServerConfig,
    control_manager: Arc<ControlManager>,
    proxy_manager: Arc<ServerProxyManager>,
    visitor_manager: Arc<ServerVisitorManager>,
    auth_manager: Arc<AuthManager>,
    conn_manager: ConnManager,
    tcp_listener: Option<TcpListener>,
    udp_listener: Option<UdpListener>,
    web_server: Option<WebServer>,
    metrics: Arc<MonitorMetrics>,
}

impl Server {
    pub async fn new(config: ServerConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let auth_manager = Arc::new(AuthManager::new(&config.auth)?);
        let control_manager = Arc::new(ControlManager::new());
        let proxy_manager = Arc::new(ServerProxyManager::new());
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
            web_server,
            metrics,
        })
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // 启动监控任务
        self.start_monitor_task().await;

        // 启动 Web 服务器
        if let Some(web_server) = &mut self.web_server {
            web_server.start(self).await?;
            log::info!("web server started");
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

        // 开始处理连接
        self.handle_tcp_connections().await?;
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
            loop {
                let (conn, addr) = listener.accept().await?;
                log::info!("new connection from: {:?}", addr);
                self.metrics.increment_connections();
                let control_manager = self.control_manager.clone();
                let proxy_manager = self.proxy_manager.clone();
                let visitor_manager = self.visitor_manager.clone();
                let auth_manager = self.auth_manager.clone();
                let metrics = self.metrics.clone();

                tokio::spawn(async move {
                    if let Err(e) = Self::handle_connection(
                        conn,
                        control_manager,
                        proxy_manager,
                        visitor_manager,
                        auth_manager,
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = ControlConn::new(Box::new(conn));
        let msg = conn.read_message().await?;

        match msg {
            Message::Login(login_msg) => {
                // 验证登录
                auth_manager.verify_login(&login_msg.user, &login_msg.client_id).await?;

                // 创建控制器
                let control = Control::new(
                    conn,
                    login_msg.run_id,
                    login_msg.user,
                    login_msg.client_id,
                    proxy_manager,
                    visitor_manager,
                    auth_manager,
                );

                // 添加到控制器管理器
                control_manager.add(login_msg.run_id.clone(), control).await?;

                // 启动控制器
                let control = control_manager.get(&login_msg.run_id).await;
                if let Some(control) = control {
                    tokio::spawn(async move {
                        let mut control = control.lock().await;
                        if let Err(e) = control.run().await {
                            log::error!("control run error: {:?}", e);
                        }
                    });
                }
            }
            Message::NewWorkConn(new_work_conn_msg) => {
                // 处理新工作连接
                log::info!("new work connection for proxy: {}", new_work_conn_msg.proxy_name);
                // 暂时关闭连接
                drop(conn);
            }
            Message::NewVisitorConn(new_visitor_conn_msg) => {
                // 处理新访问者连接
                log::info!("new visitor connection for proxy: {}", new_visitor_conn_msg.proxy_name);
                // 暂时关闭连接
                drop(conn);
            }
            _ => {
                log::warn!("unexpected message: {:?}", msg);
                drop(conn);
            }
        }
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
            web_server: None,
            metrics: self.metrics.clone(),
        }
    }
}
