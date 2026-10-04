//! Server 主体：监听器编排、连接处理与配置热重载

use rust_frp_auth::AuthManager;
use rust_frp_config::ServerConfig;
use rust_frp_core::{ControlConn, Message};
use rust_frp_net::{
    AnyConn, ConnManager, KcpConn, KcpListener, MuxSession, TcpListener, TlsConfig, UdpListener,
    TCP_MUX_MAGIC,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, RwLock};

use crate::*;

/// 登录/工作连接握手阶段的最长等待时间。
///
/// 认证前的读操作必须受此超时约束（安全评审 P0-1）：
/// 未认证连接不允许永久占用服务端任务与缓冲区。
pub(crate) const LOGIN_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// 全局并发连接上限（安全评审 P1-4 纵深防御）：
/// 即使所有预认证读都有超时，攻击者仍可用大量短连接消耗任务/内存预算，
/// 这里对控制口 + 工作连接口的在途连接总数做硬性兜底。
pub(crate) const MAX_INFLIGHT_CONNECTIONS: usize = 4096;

pub(crate) fn conn_limiter() -> &'static std::sync::Arc<tokio::sync::Semaphore> {
    static SEM: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    SEM.get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_CONNECTIONS)))
}

/// 尝试获取连接许可；达到上限时返回 None（调用方应立即关闭连接，不接受排队）
pub(crate) fn try_acquire_conn_permit() -> Option<tokio::sync::OwnedSemaphorePermit> {
    std::sync::Arc::clone(conn_limiter())
        .try_acquire_owned()
        .ok()
}

/// 写方向超时（安全评审 P1-2）：恶意客户端可以把 TCP 窗口压到 0，
/// 让服务端 write 无限阻塞、钉死控制/工作连接任务。
/// 30s 内对端没有消费数据即视为连接失效。
pub(crate) const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// STCP/XTCP 访问签名的时间戳最大允许偏差（秒）：
/// 签名绑定 timestamp，超出窗口的请求视为重放，直接拒绝。
pub(crate) const STCP_SIGN_MAX_AGE_SECS: i64 = 120;

/// 带超时的消息写入（工作连接握手等原始流路径使用）
pub(crate) async fn write_message_with_timeout<T: tokio::io::AsyncWrite + Unpin>(
    conn: &mut T,
    msg: &Message,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tokio::time::timeout(WRITE_TIMEOUT, rust_frp_core::write_message(conn, msg))
        .await
        .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
            "write timeout: peer is not consuming data (zero-window?)".into()
        })?
}

/// 服务端共享管理器集合：连接处理链路（TCP/TLS/KCP/mux）统一打包传递，
/// 替代 8-10 个独立 Arc 参数（评审 P2：too_many_arguments 收敛）
#[derive(Clone)]
pub(crate) struct ServerManagers {
    pub control_manager: Arc<ControlManager>,
    pub proxy_manager: Arc<ServerProxyManager>,
    pub visitor_manager: Arc<ServerVisitorManager>,
    pub auth_manager: Arc<AuthManager>,
    pub proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
    pub xtcp_visitors: Arc<RwLock<std::collections::HashMap<String, String>>>,
    pub stcp_bridge_manager: Arc<StcpBridgeManager>,
    pub work_conn_manager: Arc<ServerWorkConnManager>,
}

/// 服务器服务
// 个别监听器字段（vhost_* / work_conn_listener）仅在对应功能启用时读取
#[allow(dead_code)]
pub struct Server {
    config: ServerConfig,
    pub(crate) control_manager: Arc<ControlManager>,
    pub(crate) proxy_manager: Arc<ServerProxyManager>,
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
    pub(crate) metrics: Arc<MonitorMetrics>,
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
    pub(crate) reload_tx: Option<tokio::sync::mpsc::Sender<()>>,
}

impl Server {
    /// 打包共享管理器集合（全部为 Arc 克隆，代价 O(1)）
    pub(crate) fn managers(&self) -> ServerManagers {
        ServerManagers {
            control_manager: self.control_manager.clone(),
            proxy_manager: self.proxy_manager.clone(),
            visitor_manager: self.visitor_manager.clone(),
            auth_manager: self.auth_manager.clone(),
            proxy_owners: self.proxy_owners.clone(),
            xtcp_visitors: self.xtcp_visitors.clone(),
            stcp_bridge_manager: self.stcp_bridge_manager.clone(),
            work_conn_manager: self.work_conn_manager.clone(),
        }
    }

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
                    Some(TlsConfig::new_server_with_runtime_cert()?)
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
                "tls_only requires transport.tls.enable = true (with cert/key or runtime-generated cert)"
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
        // 启动 HTTP 虚拟主机连接处理任务（先借用局部监听器，再存入字段，避免回读后 unwrap）
        let http_vhost_router = self.proxy_manager.get_http_vhost_router();
        let metrics = self.metrics.clone();
        self.start_http_vhost_handler(&vhost_listener, http_vhost_router, metrics)
            .await?;
        self.vhost_http_listener = Some(vhost_listener);

        // 启动 HTTPS 虚拟主机监听器
        let tls_config = self.conn_manager.get_tls_config();
        if let Some(tls_cfg) = tls_config {
            let vhost_https_port = self.config.vhost_https_port.unwrap_or(9091);
            log::info!("HTTPS vhost listener started on {}", vhost_https_port);
            let addr =
                format!("{}:{}", self.config.bind_addr, vhost_https_port).parse::<SocketAddr>()?;
            let vhost_listener = HttpsVhostListener::bind(&addr, tls_cfg.clone()).await?;
            log::info!("HTTPS vhost listener started on {}", addr);

            // 启动 HTTPS 虚拟主机连接处理任务（先借用局部监听器，再存入字段，避免回读后 unwrap）
            let http_vhost_router = self.proxy_manager.get_http_vhost_router();
            let metrics = self.metrics.clone();
            self.start_https_vhost_handler(&vhost_listener, http_vhost_router, metrics)
                .await?;
            self.vhost_https_listener = Some(vhost_listener);
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
                            let managers = ServerManagers {
                                control_manager: control_manager.clone(),
                                proxy_manager: proxy_manager.clone(),
                                visitor_manager: visitor_manager.clone(),
                                auth_manager: auth_manager.clone(),
                                proxy_owners: proxy_owners.clone(),
                                xtcp_visitors: xtcp_visitors.clone(),
                                stcp_bridge_manager: stcp_bridge_manager.clone(),
                                work_conn_manager: work_conn_manager.clone(),
                            };
                            let m = metrics.clone();

                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_kcp_connection(
                                    kcp_conn,
                                    managers,
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
                    // 全局连接上限（P1-4）：超过即直接拒绝，不做排队
                    let permit = match try_acquire_conn_permit() {
                        Some(p) => p,
                        None => {
                            log::warn!(
                                "Inflight connection limit ({}) reached, rejecting work conn from {:?}",
                                MAX_INFLIGHT_CONNECTIONS,
                                addr
                            );
                            continue;
                        }
                    };
                    let cm = control_manager.clone();
                    let wcm = work_conn_manager.clone();
                    let am = auth_manager.clone();
                    let sbm = stcp_bridge_manager.clone();
                    let tls_config = tls_config.clone();

                    tokio::spawn(async move {
                        let _permit = permit;
                        // 嗅探首字节：0x16 = TLS ClientHello，其余视为明文协议
                        // 安全：peek 受握手超时约束，未认证连接不允许无限等待首字节
                        let mut first_byte = [0u8; 1];
                        let peek_result =
                            tokio::time::timeout(LOGIN_READ_TIMEOUT, conn.peek(&mut first_byte))
                                .await;
                        let n = match peek_result {
                            Ok(Ok(n)) => n,
                            Ok(Err(e)) => {
                                log::debug!("Work conn peek failed from {:?}: {}", addr, e);
                                return;
                            }
                            Err(_) => {
                                log::debug!(
                                    "Work conn peek timed out from {:?} after {:?}",
                                    addr,
                                    LOGIN_READ_TIMEOUT
                                );
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
                                            log_work_conn_error(e.as_ref());
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
                                    log_work_conn_error(e.as_ref());
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
        //
        // 安全：认证前的握手读必须带超时（P0-1），首帧用预认证上限（P0-2）。
        let msg = match tokio::time::timeout(
            LOGIN_READ_TIMEOUT,
            rust_frp_core::read_message_with_limit(
                &mut conn,
                rust_frp_core::MAX_PREAUTH_MESSAGE_SIZE,
            ),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                log::warn!(
                    "Work conn handshake timed out after {:?}",
                    LOGIN_READ_TIMEOUT
                );
                return Err("work conn handshake timeout".into());
            }
        };

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
                    write_message_with_timeout(&mut conn, &resp).await?;
                    return Err("Unknown run_id".into());
                }

                // 验证 sign_key（fail-closed + 常量时间比较）
                //
                // - 服务端配置了 token（即存在 encryption_key）时**必须**校验，
                //   任何"取不到期望值"或"不匹配"的情况都直接拒绝，不再放行；
                // - 未配置 token 时本层不适用（登录阶段同样不做鉴权）；
                // - 比较走常量时间，避免通过响应时延侧信道逐字节爆破 sign_key。
                if auth_manager.encryption_key().is_some() {
                    let expected_key = match auth_manager
                        .generate_work_conn_sign_key(&work_msg.run_id)
                        .await
                    {
                        Ok(key) => key,
                        Err(e) => {
                            log::error!(
                                "Rejecting work conn: cannot derive sign_key for run_id {}: {:?}",
                                work_msg.run_id,
                                e
                            );
                            let resp = Message::StartWorkConn(rust_frp_core::StartWorkConnMsg {
                                error: "Sign key verification unavailable".to_string(),
                                src_addr: String::new(),
                                src_port: 0,
                                dst_addr: String::new(),
                                dst_port: 0,
                            });
                            write_message_with_timeout(&mut conn, &resp).await?;
                            return Err("Sign key verification unavailable".into());
                        }
                    };

                    if !constant_time_eq(&work_msg.sign_key, &expected_key) {
                        log::error!(
                            "Sign key mismatch for proxy: {} (run_id {})",
                            work_msg.proxy_name,
                            work_msg.run_id
                        );
                        let resp = Message::StartWorkConn(rust_frp_core::StartWorkConnMsg {
                            error: "Sign key verification failed".to_string(),
                            src_addr: String::new(),
                            src_port: 0,
                            dst_addr: String::new(),
                            dst_port: 0,
                        });
                        write_message_with_timeout(&mut conn, &resp).await?;
                        return Err("Sign key mismatch".into());
                    }
                }

                // 应用层加密（fail-closed）：客户端请求加密但服务端未配 token 时拒绝；
                // 包装在验签后、入池/桥接前，池与 STCP 桥接路径自动获得加密能力
                let conn: AnyConn = if work_msg.use_encryption {
                    match auth_manager.encryption_key() {
                        Some(key) => {
                            Box::new(rust_frp_net::crypto::EncryptedStream::new(conn, key)?)
                        }
                        None => {
                            log::error!(
                                "Rejecting encrypted work conn for proxy {}: server has no token configured",
                                work_msg.proxy_name
                            );
                            let resp = Message::StartWorkConn(rust_frp_core::StartWorkConnMsg {
                                error: "Server cannot derive encryption key (no token)".to_string(),
                                src_addr: String::new(),
                                src_port: 0,
                                dst_addr: String::new(),
                                dst_port: 0,
                            });
                            write_message_with_timeout(&mut conn, &resp).await?;
                            return Err("use_encryption requested but server has no token".into());
                        }
                    }
                } else {
                    conn
                };

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
        let visitor_addr = conn.peer_addr().unwrap_or_else(|_| {
            "0.0.0.0:0"
                .parse()
                .expect("constant socket addr is always valid")
        });
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
                    metrics_data["bytes_sent"].as_u64().unwrap_or(0) / 1024,
                    metrics_data["bytes_received"].as_u64().unwrap_or(0) / 1024
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
                        Some(TlsConfig::new_server_with_runtime_cert()?)
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
                            // 全局连接上限（P1-4）：超过即直接拒绝，不做排队
                            let permit = match try_acquire_conn_permit() {
                                Some(p) => p,
                                None => {
                                    self.metrics.decrement_connections();
                                    log::warn!(
                                        "Inflight connection limit ({}) reached, rejecting control conn from {:?}",
                                        MAX_INFLIGHT_CONNECTIONS,
                                        addr
                                    );
                                    continue;
                                }
                            };
                            let managers = self.managers();
                            let metrics = self.metrics.clone();
                            let tls_config = tls_config.clone();

                            tokio::spawn(async move {
                                let _conn_permit = permit;
                                if let Err(e) =
                                    Self::handle_connection(conn, managers, tls_config).await
                                {
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
                    // 全局连接上限（P1-4）：超过即直接拒绝，不做排队
                    let permit = match try_acquire_conn_permit() {
                        Some(p) => p,
                        None => {
                            self.metrics.decrement_connections();
                            log::warn!(
                                "Inflight connection limit ({}) reached, rejecting control conn from {:?}",
                                MAX_INFLIGHT_CONNECTIONS,
                                addr
                            );
                            continue;
                        }
                    };
                    let managers = self.managers();
                    let metrics = self.metrics.clone();
                    let tls_config = tls_config.clone();

                    tokio::spawn(async move {
                        let _conn_permit = permit;
                        if let Err(e) = Self::handle_connection(conn, managers, tls_config).await {
                            log::error!("handle connection error: {:?}", e);
                        }
                        metrics.decrement_connections();
                    });
                }
            }
        }
        Ok(())
    }

    async fn handle_connection(
        mut conn: tokio::net::TcpStream,
        managers: ServerManagers,
        tls_config: Option<TlsConfig>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let ServerManagers {
            control_manager,
            proxy_manager,
            visitor_manager,
            auth_manager,
            proxy_owners,
            xtcp_visitors,
            stcp_bridge_manager,
            work_conn_manager,
        } = managers;
        // 首字节嗅探：TCP_MUX_MAGIC = tcp_mux 客户端（多路复用路径）
        // 安全：入口嗅探与 TLS 握手都必须受握手超时约束（P0-1），
        // 未认证连接不允许永久占用任务。
        let mut first = [0u8; 1];
        let sniff = tokio::time::timeout(LOGIN_READ_TIMEOUT, conn.peek(&mut first)).await;
        match sniff {
            // 对端一直不发首字节：直接断开，不让未认证连接占用任务
            Err(_) => {
                log::debug!(
                    "Control conn sniff timed out from peer after {:?}",
                    LOGIN_READ_TIMEOUT
                );
                return Err("control conn sniff timeout".into());
            }
            Ok(Err(e)) => {
                log::debug!("Control conn sniff failed: {}", e);
                return Err(format!("control conn sniff failed: {}", e).into());
            }
            Ok(Ok(_)) => {}
        }
        if first[0] == TCP_MUX_MAGIC {
            // 消费 magic 字节（peek 不消费；不读掉会污染后续 TLS 握手）
            let mut b = [0u8; 1];
            conn.read_exact(&mut b).await?;
            log::info!("tcp_mux connection detected");
            return Self::handle_mux_connection(
                conn,
                ServerManagers {
                    control_manager,
                    proxy_manager,
                    visitor_manager,
                    auth_manager,
                    proxy_owners,
                    xtcp_visitors,
                    stcp_bridge_manager,
                    work_conn_manager,
                },
                tls_config,
            )
            .await;
        }

        // 工作连接 TLS 协商标志：与控制连接共用同一 TLS 配置
        let work_conn_tls = tls_config.is_some();
        let conn = if let Some(tls_config) = tls_config {
            // 处理 TLS 连接
            let tls_stream =
                match tokio::time::timeout(LOGIN_READ_TIMEOUT, tls_config.accept(conn)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        global_metrics().incr_tls_rejects();
                        log::warn!("TLS accept failed: {}", e);
                        return Err(format!("TLS accept failed: {}", e).into());
                    }
                    Err(_) => {
                        global_metrics().incr_tls_rejects();
                        log::warn!("TLS handshake timed out after {:?}", LOGIN_READ_TIMEOUT);
                        return Err("TLS handshake timeout".into());
                    }
                };
            ControlConn::new(Box::new(tls_stream))
        } else {
            // 处理普通 TCP 连接
            ControlConn::new(Box::new(conn))
        };

        Self::spawn_control(
            conn,
            ServerManagers {
                control_manager,
                proxy_manager,
                visitor_manager,
                auth_manager,
                proxy_owners,
                xtcp_visitors,
                stcp_bridge_manager,
                work_conn_manager,
            },
            work_conn_tls,
        );

        Ok(())
    }

    /// 启动控制连接处理任务（登录注册 + 控制循环 + 退出清理）
    ///
    /// 返回任务句柄：多路复用路径在控制流退出后据此关闭会话。
    fn spawn_control(
        conn: ControlConn,
        managers: ServerManagers,
        work_conn_tls: bool,
    ) -> tokio::task::JoinHandle<()> {
        let ServerManagers {
            control_manager,
            proxy_manager,
            auth_manager,
            proxy_owners,
            xtcp_visitors,
            stcp_bridge_manager,
            work_conn_manager,
            ..
        } = managers;
        // 创建登录通知通道
        let (login_tx, mut login_rx) = mpsc::channel::<String>(1);

        // 创建消息发送通道（用于 Control::run 统一处理消息发送）
        let (msg_tx, msg_rx) = mpsc::channel::<Message>(100);

        // cm 在 Control::new 消费 control_manager 之前取出（任务收尾清理用）
        let cm = control_manager.clone();

        // 创建控制器（不需要 Arc<Mutex>，因为只在一个任务中使用）
        let mut control = Control::new(ControlDeps {
            conn,
            run_id: "".to_string(),
            user: "".to_string(),
            client_id: "".to_string(),
            proxy_manager,
            auth_manager,
            control_manager,
            proxy_owners,
            xtcp_visitors,
            login_tx: Some(login_tx),
            msg_tx: Some(msg_tx),
            stcp_bridge_manager,
            work_conn_manager,
            work_conn_tls,
        });

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
    async fn handle_mux_connection(
        conn: tokio::net::TcpStream,
        managers: ServerManagers,
        tls_config: Option<TlsConfig>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let ServerManagers {
            control_manager,
            proxy_manager,
            visitor_manager,
            auth_manager,
            proxy_owners,
            xtcp_visitors,
            stcp_bridge_manager,
            work_conn_manager,
        } = managers;
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
        let cm = control_manager.clone();
        let wcm = work_conn_manager.clone();
        let control_handle = Self::spawn_control(
            ControlConn::new(control_stream),
            ServerManagers {
                control_manager,
                proxy_manager,
                visitor_manager,
                auth_manager,
                proxy_owners,
                xtcp_visitors,
                stcp_bridge_manager,
                work_conn_manager,
            },
            work_conn_tls,
        );

        // 后续流 = 工作连接，逐条分发
        let dispatch_session = session.clone();
        let dispatch = tokio::spawn(async move {
            while let Ok(stream) = dispatch_session.accept_stream().await {
                log::info!("New mux work stream");
                let cm = cm.clone();
                let wcm = wcm.clone();
                let am = am.clone();
                let sbm = sbm.clone();
                tokio::spawn(async move {
                    if let Err(e) = Server::process_work_conn(stream, cm, wcm, am, sbm).await {
                        log_work_conn_error(e.as_ref());
                    }
                });
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

    async fn handle_kcp_connection(
        kcp_conn: KcpConn,
        managers: ServerManagers,
        work_conn_tls: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let ServerManagers {
            control_manager,
            proxy_manager,
            auth_manager,
            proxy_owners,
            xtcp_visitors,
            stcp_bridge_manager,
            work_conn_manager,
            ..
        } = managers;
        let conn = ControlConn::new(Box::new(kcp_conn));

        let (login_tx, mut login_rx) = mpsc::channel::<String>(1);
        let (msg_tx, msg_rx) = mpsc::channel::<Message>(100);

        let cm = control_manager.clone();

        let mut control = Control::new(ControlDeps {
            conn,
            run_id: "".to_string(),
            user: "".to_string(),
            client_id: "".to_string(),
            proxy_manager,
            auth_manager,
            control_manager,
            proxy_owners,
            xtcp_visitors,
            login_tx: Some(login_tx),
            msg_tx: Some(msg_tx),
            stcp_bridge_manager,
            work_conn_manager,
            work_conn_tls,
        });

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
pub(crate) async fn reload_server_config(
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
