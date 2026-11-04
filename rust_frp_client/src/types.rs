//! 从 lib.rs 拆出的 types 实现。

use super::*;

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

pub(super) type WorkConnSenderMap =
    RwLock<std::collections::HashMap<String, mpsc::Sender<(tokio::net::TcpStream, Vec<u8>)>>>;

/// 类型擦除的控制连接传输（TCP / TLS / WebSocket / KCP / mux 流统一类型）
pub(super) type ControlIo = Box<dyn rust_frp_net::FrpConn>;

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
    pub(super) proxies: RwLock<std::collections::HashMap<String, rust_frp_config::ProxyConfig>>,
    pub(super) listeners:
        RwLock<std::collections::HashMap<String, std::sync::Arc<tokio::net::TcpListener>>>,
    pub(super) work_conn_handlers:
        RwLock<std::collections::HashMap<String, tokio::task::JoinHandle<()>>>,
    pub(super) work_conn_manager: Option<Arc<WorkConnManager>>,
    /// 传输层全局带宽限制（transport.bandwidth_limit），作为代理级配置的回落值
    pub(super) default_bandwidth_limit: Option<String>,
    /// per-proxy 累计流量（键为代理名）
    pub(super) traffic: RwLock<std::collections::HashMap<String, Arc<ProxyTraffic>>>,
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
    pub(super) async fn traffic_counter(&self, proxy_name: &str) -> Arc<ProxyTraffic> {
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
                                Err(e) => rust_frp_util::log_bridge_error(
                                    &format!("Bridge error for proxy {proxy_name_clone}"),
                                    e.as_ref(),
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
        for handle in handlers.values() {
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
    pub(super) visitors: RwLock<std::collections::HashMap<String, rust_frp_config::VisitorConfig>>,
    /// visitor 任务句柄（按 visitor.name 索引）。
    ///
    /// 为什么需要它：控制连接断开重连时主循环会走 `clear()` 再按新
    /// `run_id` 重新 spawn `start_stcp_visitor`。若 clear 只清配置表而不
    /// abort 旧任务，旧任务的 listener 仍占用本地端口（bind 报 AddrInUse，
    /// 新监听永远起不来），且旧任务的 `stcp_tx` 已随旧控制连接关闭，
    /// 之后 accept 到的连接全部 "channel closed"——隧道静默死亡且不会
    /// 自愈，只能手动重启 frpc。
    pub(super) visitor_tasks:
        RwLock<std::collections::HashMap<String, tokio::task::JoinHandle<()>>>,
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
            visitor_tasks: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// 注册（或替换）一个 visitor 任务的句柄。
    ///
    /// 同名重复注册时先 abort 旧任务：热重载改了 visitor 配置、或异常
    /// 路径重复 spawn，都不允许两个任务同时监听同一个本地端口。
    pub async fn register_visitor_task(&self, name: String, handle: tokio::task::JoinHandle<()>) {
        let mut tasks = self.visitor_tasks.write().await;
        if let Some(old) = tasks.insert(name, handle) {
            old.abort();
        }
    }

    /// abort 并摘除单个 visitor 任务（管理端 API 用）
    pub async fn abort_visitor_task(&self, name: &str) {
        let handle = self.visitor_tasks.write().await.remove(name);
        if let Some(h) = handle {
            h.abort();
        }
    }

    /// abort 全部 visitor 任务并等待它们真正退出。
    ///
    /// 只 abort 不 await 是不够的：abort 是异步生效的，任务要到下一个
    /// await 点才被 drop，listener socket 也随之释放。若立刻重连并 spawn
    /// 新任务 bind 同一端口，仍可能撞上 AddrInUse。这里 await 兜底
    /// （带超时：极端情况下任务卡住也不阻塞重连主循环，bind 重试会兜住）。
    pub async fn abort_all_visitor_tasks(&self) {
        let handles = {
            let mut tasks = self.visitor_tasks.write().await;
            tasks
                .drain()
                .map(|(_, h)| h)
                .collect::<Vec<tokio::task::JoinHandle<()>>>()
        };
        for h in &handles {
            h.abort();
        }
        for h in handles {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), h).await;
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
        // 先 abort 并等待旧 visitor 任务退出（释放本地监听端口），
        // 再清配置表——顺序反了会让重连后的新任务 bind 失败
        self.abort_all_visitor_tasks().await;
        let mut visitors = self.visitors.write().await;
        visitors.clear();
        log::info!("Visitor manager cleared");
    }
}
