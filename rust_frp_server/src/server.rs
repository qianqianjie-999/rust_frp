//! Server 主体：监听器编排、连接处理与配置热重载

use rust_frp_auth::AuthManager;
use rust_frp_config::ServerConfig;
use rust_frp_core::{ControlConn, Message};
use rust_frp_net::{
    AnyConn, ConnManager, KcpConn, KcpListener, MuxSession, QuicConnection, QuicListener,
    QuicOptions, TcpListener, TlsConfig, TCP_MUX_MAGIC,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, RwLock};

use crate::*;

pub(crate) type AuthRuntime = Arc<RwLock<Arc<AuthManager>>>;

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

/// 嗅探字节是否构成 WebSocket 升级请求前缀（`GET `）
///
/// 兼容「只读到部分字节」的情况（"G" / "GE" / "GET"），因此用双向前缀判断。
fn is_websocket_prefix(bytes: &[u8]) -> bool {
    !bytes.is_empty() && (bytes.starts_with(b"GET ") || b"GET ".starts_with(bytes))
}

/// 无法取得对端地址时的占位（仅用于日志展示）
fn placeholder_addr() -> SocketAddr {
    SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0))
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
    pub auth_runtime: AuthRuntime,
    pub proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
    pub xtcp_visitors: Arc<RwLock<std::collections::HashMap<String, String>>>,
    pub stcp_bridge_manager: Arc<StcpBridgeManager>,
    pub work_conn_manager: Arc<ServerWorkConnManager>,
    pub plugin_manager: Arc<rust_frp_plugin::server_plugin::Manager>,
    /// 服务器工作连接端口（数据/控制分离的专用数据端口），
    /// 通过 LoginRespMsg 下发给客户端，免去客户端猜测 server_port+1000
    pub work_conn_port: u16,
}

/// 优雅关闭排空轮询间隔
const DRAIN_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// 出站 TCP 复用缓存大小（`ConnManager` 内部池）
///
/// 与 `transport.pool_count`（预建工作连接数）无关：后者默认 0，若直接拿它
/// 当信号量容量，`ConnManager::get()` 会永久阻塞。
const CONN_REUSE_POOL_SIZE: usize = 10;

/// 服务器服务
pub struct Server {
    config: ServerConfig,
    pub(crate) control_manager: Arc<ControlManager>,
    pub(crate) proxy_manager: Arc<ServerProxyManager>,
    visitor_manager: Arc<ServerVisitorManager>,
    auth_runtime: AuthRuntime,
    conn_manager: ConnManager,
    tcp_listener: Option<TcpListener>,
    vhost_http_listener: Option<HttpVhostListener>,
    vhost_https_listener: Option<HttpsVhostListener>,
    /// 工作连接监听器
    work_conn_listener: Option<std::sync::Arc<tokio::net::TcpListener>>,
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
    /// 优雅关闭通知（控制连接 accept 循环据此退出并按超时排空存量连接）
    shutdown_notify: Arc<tokio::sync::Notify>,
    /// 非控制 / 非代理的 ingress accept 任务，shutdown 时统一中止
    ingress_tasks: Vec<tokio::task::JoinHandle<()>>,
    /// 服务端 HTTP 插件管理器（控制面回调）
    plugin_manager: Arc<rust_frp_plugin::server_plugin::Manager>,
}

impl Server {
    /// 只读访问服务端配置（管理端 API 构造 serverinfo 用）
    pub(crate) fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// 打包共享管理器集合（全部为 Arc 克隆，代价 O(1)）
    pub(crate) fn managers(&self) -> ServerManagers {
        ServerManagers {
            control_manager: self.control_manager.clone(),
            proxy_manager: self.proxy_manager.clone(),
            visitor_manager: self.visitor_manager.clone(),
            auth_runtime: self.auth_runtime.clone(),
            proxy_owners: self.proxy_owners.clone(),
            xtcp_visitors: self.xtcp_visitors.clone(),
            stcp_bridge_manager: self.stcp_bridge_manager.clone(),
            work_conn_manager: self.work_conn_manager.clone(),
            plugin_manager: self.plugin_manager.clone(),
            work_conn_port: self
                .config
                .work_conn_port
                .unwrap_or(self.config.bind_port + 1000),
        }
    }

    pub async fn new(
        config: ServerConfig,
        config_path: Option<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let auth_manager = Arc::new(AuthManager::new(&config.auth).map_err(|e| e.to_string())?);
        let auth_runtime = Arc::new(RwLock::new(auth_manager));
        // P1/B4 登录节流 + P1/B1 client_id 策略 + P4 接管指纹判据：
        // 统一由 ControlManager 承载（它已被逐连接共享，无需再穿透调用栈）
        let login_throttle = crate::login_throttle::LoginThrottle::new(
            config.auth.login_max_failures,
            config.auth.login_lockout_secs,
        );
        if let Some(t) = &login_throttle {
            log::info!(
                "control login throttle enabled: lock after {} consecutive failures for {}s",
                t.max_failures(),
                t.lockout().as_secs()
            );
        } else {
            log::info!("control login throttle disabled (auth.login_max_failures = 0)");
        }
        log::info!(
            "client_id policy = {:?}; kick requires matching client certificate = {}",
            config.auth.client_id_policy,
            config.auth.kick_require_same_cert
        );
        let control_manager = Arc::new(ControlManager::with_security(
            login_throttle,
            config.auth.client_id_policy,
            config.auth.kick_require_same_cert,
        ));
        let http_vhost_router = Arc::new(HttpVhostRouter::new());
        let work_conn_manager = Arc::new(ServerWorkConnManager::new(
            config.transport.effective_max_pool_count() as usize,
        ));
        let proxy_owners = Arc::new(RwLock::new(std::collections::HashMap::new()));
        // 服务端 HTTP 插件管理器（未配置 http_plugins 时为空管理器，回调直接短路）
        let plugin_manager = Arc::new(rust_frp_plugin::server_plugin::Manager::from_configs(
            &config.http_plugins,
        ));
        let proxy_manager = Arc::new(ServerProxyManager::new(
            http_vhost_router,
            proxy_owners.clone(),
            control_manager.clone(),
            work_conn_manager.clone(),
            ProxyManagerOptions {
                allow_ports: config.allow_ports.clone(),
                max_ports_per_user: config.max_ports_per_user,
                custom_domains_allowlist: config.custom_domains_allowlist.clone(),
                tcpmux_port: config.tcpmux_http_connect_port,
                plugin_manager: plugin_manager.clone(),
            },
        ));
        // 安全评审 P2：开启 vhost/tcpmux 却没配域名白名单时，任何已认证客户端
        // 都能注册任意 custom_domains 抢占 Host 匹配。默认允许但显式告警。
        if config.custom_domains_allowlist.is_empty()
            && (config.vhost_http_port.is_some()
                || config.vhost_https_port.is_some()
                || config.tcpmux_http_connect_port.is_some())
        {
            log::warn!(
                "custom_domains_allowlist is empty while vhost/tcpmux ports are enabled: \
                 any authenticated client may register arbitrary custom_domains for Host \
                 matching. Set custom_domains_allowlist in frps.toml to restrict this."
            );
        }

        let visitor_manager = Arc::new(ServerVisitorManager::new());
        let metrics = Arc::new(MonitorMetrics::new());
        // 注册进程级单例，供 Control::run 等深层调用点使用
        set_global_metrics(metrics.clone());

        let tls_config = match &config.transport.tls {
            Some(tls) if tls.enable => Some(build_server_tls_config(tls)?),
            _ => None,
        };

        let conn_manager = ConnManager::new(tls_config, CONN_REUSE_POOL_SIZE);
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
            auth_runtime,
            conn_manager,
            tcp_listener: None,
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
            shutdown_notify: Arc::new(tokio::sync::Notify::new()),
            ingress_tasks: Vec::new(),
            plugin_manager,
        })
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // 启动监控任务
        self.start_monitor_task().await;
        // 启动 STCP 待桥接条目定时回收（空闲期也必须回收，见方法注释）
        self.start_stcp_bridge_gc_task().await;

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

        // KCP 端口由下方 `KcpListener::bind` 独占绑定（原通用 UdpListener 双绑会导致 AddrInUse）

        // 启动 HTTP 虚拟主机监听器
        let vhost_http_port = self.config.vhost_http_port.unwrap_or(9090);
        log::info!("HTTP vhost listener started on {}", vhost_http_port);

        let addr =
            format!("{}:{}", self.config.bind_addr, vhost_http_port).parse::<SocketAddr>()?;
        let vhost_listener = HttpVhostListener::bind(&addr).await?;
        // 启动 HTTP 虚拟主机连接处理任务（先借用局部监听器，再存入字段，避免回读后 unwrap）
        let http_vhost_router = self.proxy_manager.get_http_vhost_router();
        let metrics = self.metrics.clone();
        let handle = self
            .start_http_vhost_handler(&vhost_listener, http_vhost_router, metrics)
            .await?;
        self.ingress_tasks.push(handle);
        self.vhost_http_listener = Some(vhost_listener);

        // 启动 HTTPS 虚拟主机监听器
        // vhost HTTPS 面向浏览器等无客户端证书的访客，不能复用控制面的 mTLS 配置
        // （否则 require_client_cert = true 时握手即失败 NoCertificatesPresented）：
        // 配置了证书时用同一证书重建「无客户端认证」的 acceptor；未配置证书时
        // 回落到 conn_manager 的运行时自签配置（该配置同样可能带 mTLS verifier，
        // 故仅在无 client_ca 时复用，否则拒绝启动 vhost HTTPS）。
        let tls_config = self.config.transport.tls.as_ref();
        let tls_cfg_opt = match (
            should_start_vhost_https(tls_config),
            tls_config.and_then(|t| t.cert_file.as_deref().zip(t.key_file.as_deref())),
        ) {
            (true, Some((cert_file, key_file))) => {
                match rust_frp_net::TlsConfig::new_server(cert_file, key_file, None, false) {
                    Ok(cfg) => Some(cfg),
                    Err(e) => {
                        log::error!("failed to build vhost HTTPS TLS config: {:?}", e);
                        None
                    }
                }
            }
            (true, None) => {
                let has_client_ca = self
                    .config
                    .transport
                    .tls
                    .as_ref()
                    .and_then(|t| t.client_ca_file.as_deref())
                    .is_some();
                if has_client_ca {
                    log::error!(
                        "vhost HTTPS disabled: mTLS client_ca is set but no cert_file/key_file \
                         to build a client-auth-free vhost acceptor from"
                    );
                    None
                } else {
                    self.conn_manager.get_tls_config().cloned()
                }
            }
            (false, _) => None,
        };
        if let Some(tls_cfg) = tls_cfg_opt {
            let vhost_https_port = self.config.vhost_https_port.unwrap_or(9091);
            log::info!("HTTPS vhost listener started on {}", vhost_https_port);
            let addr =
                format!("{}:{}", self.config.bind_addr, vhost_https_port).parse::<SocketAddr>()?;
            let vhost_listener = HttpsVhostListener::bind(&addr, tls_cfg.clone()).await?;
            log::info!("HTTPS vhost listener started on {}", addr);

            // 启动 HTTPS 虚拟主机连接处理任务（先借用局部监听器，再存入字段，避免回读后 unwrap）
            let http_vhost_router = self.proxy_manager.get_http_vhost_router();
            let metrics = self.metrics.clone();
            let handle = self
                .start_https_vhost_handler(&vhost_listener, http_vhost_router, metrics)
                .await?;
            self.ingress_tasks.push(handle);
            self.vhost_https_listener = Some(vhost_listener);
        } else {
            log::warn!("No TLS config available, HTTPS vhost disabled");
        }

        // 启动 tcpmux HTTP CONNECT 复用器（仅在显式配置 tcpmux_http_connect_port 时）
        if let Some(tcpmux_port) = self.config.tcpmux_http_connect_port.filter(|p| *p > 0) {
            let addr =
                format!("{}:{}", self.config.bind_addr, tcpmux_port).parse::<SocketAddr>()?;
            // 显式限定：本模块内 `TcpListener` 是 rust_frp_net 的类型
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            log::info!("tcpmux HTTP CONNECT listener started on {}", addr);
            let deps = TcpMuxDeps {
                router: self.proxy_manager.get_tcpmux_router(),
                proxy_owners: self.proxy_owners.clone(),
                control_manager: self.control_manager.clone(),
                work_conn_manager: self.work_conn_manager.clone(),
                plugin_manager: self.plugin_manager.clone(),
            };
            // 监听器交由复用任务持有；关闭信号到达时随任务结束释放
            self.ingress_tasks.push(tokio::spawn(run_tcpmux_listener(
                listener,
                deps,
                self.shutdown_notify.clone(),
            )));
        }

        // 启动工作连接监听器（如果配置了 work_conn_port）
        //
        // ⚠️ 只能注册一次：此前先 from_std 原体再 from_std 克隆句柄，等于把同一个
        // socket 在 IO 多路复用器上注册了两次（Windows IOCP / epoll 皆如此），
        // 第一次连接进来就可能把 IO 驱动卡死（e2e 复现：runtime 整体冻结）。
        // 修复：单次注册，Arc 共享给监听任务与字段保活。
        let work_conn_port = self
            .config
            .work_conn_port
            .unwrap_or(self.config.bind_port + 1000);
        let work_conn_addr =
            format!("{}:{}", self.config.bind_addr, work_conn_port).parse::<SocketAddr>()?;
        let std_listener = std::net::TcpListener::bind(work_conn_addr)?;
        std_listener.set_nonblocking(true)?;
        let work_conn_listener =
            std::sync::Arc::new(tokio::net::TcpListener::from_std(std_listener)?);
        log::info!("Work connection listener started on {}", work_conn_addr);

        // 启动工作连接处理任务
        // TLS 协商：服务器启用 TLS 时工作连接监听器同步支持 TLS（嗅探 0x16 首字节），
        // tls_only 时拒绝一切明文工作连接
        let work_conn_tls_config = self.conn_manager.get_tls_config().cloned();
        let work_conn_tls_only = self.config.transport.tls_only;
        let work_conn_keepalive = self.config.transport.tcp_keepalive_idle();
        let work_conn_managers = self.managers();
        let work_conn_listener_for_task = work_conn_listener.clone();
        let handle = tokio::spawn(async move {
            Self::handle_work_connections(
                work_conn_listener_for_task,
                work_conn_managers,
                work_conn_tls_config,
                work_conn_tls_only,
                work_conn_keepalive,
            )
            .await;
        });
        self.ingress_tasks.push(handle);

        self.work_conn_listener = Some(work_conn_listener);
        // 开始处理连接
        log::info!("Starting connection handlers...");

        // 启动 KCP 连接处理器（如果启用了 KCP）
        // tls_only 下拒绝启动 KCP：KCP 为明文 UDP，无法满足强制 TLS 要求
        if self.config.kcp_bind_port.is_some() {
            if self.config.transport.tls_only {
                log::error!("tls_only is enabled, refusing to start KCP listener (plaintext UDP)");
                return Err("tls_only is enabled but KCP is plaintext UDP; disable kcp_bind_port or tls_only".into());
            }
            log::info!("KCP connection handler enabled");
            let control_manager = self.control_manager.clone();
            let proxy_manager = self.proxy_manager.clone();
            let visitor_manager = self.visitor_manager.clone();
            let auth_runtime = self.auth_runtime.clone();
            let proxy_owners = self.proxy_owners.clone();
            let metrics = self.metrics.clone();
            let work_conn_manager = self.work_conn_manager.clone();
            let stcp_bridge_manager = self.stcp_bridge_manager.clone();
            let xtcp_visitors = self.xtcp_visitors.clone();
            let plugin_manager = self.plugin_manager.clone();
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

            let kcp_work_conn_port = self
                .config
                .work_conn_port
                .unwrap_or(self.config.bind_port + 1000);

            let handle = tokio::spawn(async move {
                loop {
                    match kcp_listener.accept().await {
                        Ok((kcp_conn, addr)) => {
                            log::info!("new KCP connection from: {:?}", addr);
                            metrics.increment_connections();
                            let managers = ServerManagers {
                                control_manager: control_manager.clone(),
                                proxy_manager: proxy_manager.clone(),
                                visitor_manager: visitor_manager.clone(),
                                auth_runtime: auth_runtime.clone(),
                                proxy_owners: proxy_owners.clone(),
                                xtcp_visitors: xtcp_visitors.clone(),
                                stcp_bridge_manager: stcp_bridge_manager.clone(),
                                work_conn_manager: work_conn_manager.clone(),
                                plugin_manager: plugin_manager.clone(),
                                work_conn_port: kcp_work_conn_port,
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
            self.ingress_tasks.push(handle);
        }

        // QUIC 监听器（如果配置了 quic_bind_port）
        //
        // QUIC 强制 TLS 1.3，故 tls_only 天然满足（不同于明文 UDP 的 KCP，无需拒绝）。
        if let Some(quic_port) = self.config.quic_bind_port.filter(|p| *p > 0) {
            let addr = format!("{}:{}", self.config.bind_addr, quic_port).parse::<SocketAddr>()?;
            let tls = self.config.transport.tls.as_ref();
            let quic_cfg = rust_frp_net::build_quic_server_config(
                tls.and_then(|t| t.cert_file.as_deref()),
                tls.and_then(|t| t.key_file.as_deref()),
                tls.and_then(|t| t.client_ca_file.as_deref()),
                tls.map(|t| t.require_client_cert).unwrap_or(false),
                &quic_options(&self.config),
            )?;
            let listener = QuicListener::bind(addr, quic_cfg)?;
            log::info!("QUIC listener started on {} (ALPN frp)", addr);

            let managers = self.managers();
            let metrics = self.metrics.clone();
            let handle = tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok(conn) => {
                            log::info!("new QUIC connection from: {}", conn.remote_addr());
                            metrics.increment_connections();
                            let managers = managers.clone();
                            let m = metrics.clone();
                            tokio::spawn(async move {
                                Self::handle_quic_connection(conn, managers).await;
                                m.decrement_connections();
                            });
                        }
                        Err(e) => {
                            log::error!("Failed to accept QUIC connection: {:?}", e);
                            break;
                        }
                    }
                }
            });
            self.ingress_tasks.push(handle);
        }

        // 启动 TCP 连接处理器
        self.handle_tcp_connections().await?;
        self.stop_ingress().await;
        Ok(())
    }

    /// 关闭全部 ingress 监听任务；已接受的连接任务不受影响，继续由 drain 统计。
    async fn stop_ingress(&mut self) {
        self.proxy_manager.stop_all_ingress().await;
        for handle in self.ingress_tasks.drain(..) {
            handle.abort();
            let _ = handle.await;
        }
        self.vhost_http_listener.take();
        self.vhost_https_listener.take();
        self.work_conn_listener.take();
        self.web_server.take();
        log::info!("All ingress listeners stopped");
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
            *self.auth_runtime.write().await =
                Arc::new(AuthManager::new(&self.config.auth).map_err(|e| e.to_string())?);
            // 同步 ProxyManager 的端口白名单（与 reload_server_config 同理）
            self.proxy_manager
                .set_allow_ports(self.config.allow_ports.clone())
                .await;

            log::info!("Config reloaded successfully");
        }
        Ok(())
    }

    /// 优雅关闭句柄：通知后控制连接 accept 循环停止接收新连接
    pub fn shutdown_handle(&self) -> Arc<tokio::sync::Notify> {
        self.shutdown_notify.clone()
    }

    /// 等待存量连接排空（优雅关闭第二步）。
    ///
    /// 每 [`DRAIN_POLL_INTERVAL`] 采样一次当前连接数：归零返回 `true`；
    /// 超过 `timeout` 仍有余量则打印 WARN 并返回 `false`（调用方决定是否
    /// 强制退出）。注意仅统计控制连接（工作连接随客户端断开自然回收）。
    pub async fn wait_for_drain(&self, timeout: std::time::Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let current = self.metrics.current_connections();
            if current == 0 {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                log::warn!(
                    "Graceful shutdown drain timeout: {} connection(s) still active",
                    current
                );
                return false;
            }
            tokio::time::sleep(DRAIN_POLL_INTERVAL).await;
        }
    }

    pub fn set_reload_rx(&mut self, rx: tokio::sync::mpsc::Receiver<()>) {
        self.reload_rx = Some(rx);
    }

    pub fn set_reload_tx(&mut self, tx: tokio::sync::mpsc::Sender<()>) {
        self.reload_tx = Some(tx);
    }
}

impl Clone for Server {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            control_manager: self.control_manager.clone(),
            proxy_manager: self.proxy_manager.clone(),
            visitor_manager: self.visitor_manager.clone(),
            auth_runtime: self.auth_runtime.clone(),
            conn_manager: ConnManager::new(None, CONN_REUSE_POOL_SIZE),
            tcp_listener: None,
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
            shutdown_notify: self.shutdown_notify.clone(),
            ingress_tasks: Vec::new(),
            plugin_manager: self.plugin_manager.clone(),
        }
    }
}

mod control;
mod ingress;
mod reload;
mod tls_helpers;
mod transport;
mod vhost;
mod work_conn;

use self::reload::*;
use self::tls_helpers::*;

#[cfg(test)]
mod tests;
