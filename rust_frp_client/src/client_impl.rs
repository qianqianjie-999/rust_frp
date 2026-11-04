//! 从 lib.rs 拆出的 client_impl 实现。

use super::*;

/// 客户端服务
pub struct Client {
    pub(super) config: Arc<ClientConfig>,
    pub(super) control: Option<Mutex<ClientControl>>,
    pub(super) proxy_manager: Arc<ClientProxyManager>,
    pub(super) visitor_manager: Arc<ClientVisitorManager>,
    pub(super) auth_manager: Arc<AuthManager>,
    pub(super) work_conn_manager: Arc<WorkConnManager>,
    pub(super) connector: Connector,
    pub(super) web_server: Option<WebServer>,
    /// 管理端 POST /reload 经由此通知主循环执行 reload_config
    pub(super) reload_notify: Arc<tokio::sync::Notify>,
    /// 管理端 POST /stop 经由此通知主循环优雅退出
    pub(super) stop_notify: Arc<tokio::sync::Notify>,
    pub(super) config_path: Option<String>,
    pub(super) health_check_handles: Vec<tokio::task::JoinHandle<()>>,
}

/// 确保配置中的 `client_id` 是稳定的非空值：未配置时按 `fallback` 补齐，
/// 无 `fallback` 再随机生成。
///
/// 必须在**首次构造**与**配置热重载**两处都调用：热重载用文件内容整体替换
/// `ClientConfig`，若不重新补齐，`client_id` 会退回 `None`，登录时经
/// `unwrap_or(hostname)` 退化为主机名 —— 两台主机名相同的 frpc 会被服务端
/// `kick_same_client` 判定为同一客户端而无限互踢（2026-10-05 线上事故，
/// 全线端口掉线约 3 分钟）。
///
/// `fallback` 供热重载使用，必须是**当前生效的 client_id**：既不能退化为
/// `None`（→ 主机名），也不能重新随机（→ 服务端视作新客户端，与旧会话抢占
/// 同名代理）。
pub(super) fn ensure_client_id(config: &mut ClientConfig, fallback: Option<&str>) {
    if config.client_id.is_none() {
        config.client_id = Some(match fallback {
            Some(v) if !v.is_empty() => v.to_string(),
            _ => rand_id(16),
        });
    }
}

impl Client {
    pub fn new(
        mut config: ClientConfig,
        config_path: Option<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // client_id 是客户端进程的稳定标识（断线重连时复用，服务端据此把同
        // client_id 的新登录判定为重连并踢掉旧会话）。未配置时随机生成而非用
        // 主机名：同名主机上的多个 frpc 会被误判为同一客户端重连而互相踢下线
        ensure_client_id(&mut config, None);

        // 动态令牌来源（auth.tokenSource）：必须先于 AuthManager 构造解析，
        // 否则 method = "token" 且 token 为空会被判为缺少令牌而拒绝启动。
        apply_token_source(&mut config).map_err(|e| e.to_string())?;

        let auth_manager = Arc::new(AuthManager::new(&config.auth).map_err(|e| e.to_string())?);

        // 先创建可变的 proxy_manager，设置 work_conn_manager，再包装成 Arc
        let mut proxy_manager_instance = ClientProxyManager::new();
        let work_conn_manager = Arc::new(WorkConnManager::new());
        proxy_manager_instance.set_work_conn_manager(work_conn_manager.clone());
        proxy_manager_instance
            .set_default_bandwidth_limit(config.transport.bandwidth_limit.clone());
        let proxy_manager = Arc::new(proxy_manager_instance);

        let visitor_manager = Arc::new(ClientVisitorManager::new());

        // 配置整体以 Arc 共享：控制连接、工作连接、STCP visitor 等热路径
        // 只克隆指针而非深拷贝整个 ClientConfig
        let config = Arc::new(config);
        let connector = Connector::new(Arc::clone(&config))?;

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
            reload_notify: Arc::new(tokio::sync::Notify::new()),
            stop_notify: Arc::new(tokio::sync::Notify::new()),
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

        // 设置信号处理（Unix: SIGINT/SIGTERM/SIGHUP；Windows: Ctrl+C/Break/Close 控制台事件）
        #[cfg(unix)]
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        #[cfg(unix)]
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        #[cfg(unix)]
        let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        #[cfg(windows)]
        let mut sigint = tokio::signal::windows::ctrl_c()?;
        #[cfg(windows)]
        let mut sigterm = tokio::signal::windows::ctrl_break()?;
        #[cfg(windows)]
        let mut sighup = tokio::signal::windows::ctrl_close()?;

        // 配置文件变更触发热重载（与管理端 /reload、SIGHUP 共用通知通道）
        if let Some(watch_path) = self.config_path.clone() {
            let reload_notify = Arc::clone(&self.reload_notify);
            tokio::spawn(async move {
                use notify::{Event, EventKind, RecursiveMode, Watcher};
                let (watch_tx, mut watch_rx) = tokio::sync::mpsc::channel(1);
                let mut watcher =
                    match notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
                        if let Ok(event) = res {
                            if matches!(event.kind, EventKind::Modify(_)) {
                                let _ = watch_tx.blocking_send(());
                            }
                        }
                    }) {
                        Ok(w) => w,
                        Err(e) => {
                            log::warn!("Failed to create file watcher: {}", e);
                            return;
                        }
                    };

                if let Err(e) = watcher.watch(
                    std::path::Path::new(&watch_path),
                    RecursiveMode::NonRecursive,
                ) {
                    log::warn!("Failed to watch config file {}: {}", watch_path, e);
                    return;
                }
                log::info!("Watching config file for changes: {}", watch_path);

                loop {
                    if watch_rx.recv().await.is_none() {
                        break;
                    }
                    // 500ms 防抖：编辑器保存常产生多次 Modify 事件
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    // 把防抖窗口内积压的事件一并吃掉。只 sleep 不排空的话，一次保存
                    // 产生的 N 个 Modify 会排成 N 次全量重载（各间隔 500ms）——现场实测
                    // 5 次重载/2.5s，每次都断开控制连接重新登录，visitor 反复重建。
                    while watch_rx.try_recv().is_ok() {}
                    log::info!("Config file changed, triggering config reload...");
                    reload_notify.notify_one();
                }
            });
        }

        // 重连配置：首次断线立即重连（0ms），失败后 1s 起步指数退避，封顶 30s
        let mut reconnect_delay_ms: u64 = 0;
        let max_reconnect_delay_ms: u64 = 15_000;

        // 热重载通知：管理端 POST /reload、SIGHUP、配置文件变更共用同一通道
        let reload_notify = Arc::clone(&self.reload_notify);
        let mut reload_requested = false;

        // 退出通知：管理端 POST /stop（`frpc stop`）
        let stop_notify = Arc::clone(&self.stop_notify);

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
                        let server_work_conn_port = control.server_work_conn_port();
                        let xtcp_registry = control.xtcp_registry();
                        drop(control);
                        for visitor in &self.config.visitors {
                            match visitor.r#type.as_str() {
                                "stcp" | "xtcp" => {
                                    let bind_addr =
                                        format!("{}:{}", visitor.bind_addr, visitor.bind_port);
                                    let proxy_name = visitor.server_name.clone();
                                    let stcp_tx = stcp_tx.clone();
                                    let cfg = Arc::clone(&self.config);
                                    let rid = run_id.clone();
                                    let reg = xtcp_registry.clone();
                                    let handle = tokio::spawn(async move {
                                        start_stcp_visitor(StcpVisitorDeps {
                                            bind_addr,
                                            proxy_name,
                                            stcp_tx,
                                            run_id: rid,
                                            config: cfg,
                                            work_conn_tls,
                                            server_work_conn_port,
                                            xtcp_registry: reg,
                                        })
                                        .await;
                                    });
                                    // 登记句柄：断线重连 clear() 时 abort 旧任务，
                                    // 否则旧 listener 占着端口，新任务 bind 必失败
                                    self.visitor_manager
                                        .register_visitor_task(visitor.name.clone(), handle)
                                        .await;
                                }
                                // sudp visitor：监听本地 UDP，按源地址建独立隧道会话
                                "sudp" => {
                                    let bind_addr =
                                        format!("{}:{}", visitor.bind_addr, visitor.bind_port);
                                    let proxy_name = visitor.server_name.clone();
                                    let stcp_tx = stcp_tx.clone();
                                    let cfg = Arc::clone(&self.config);
                                    let rid = run_id.clone();
                                    let swcp = server_work_conn_port;
                                    let handle = tokio::spawn(async move {
                                        start_sudp_visitor(bind_addr, proxy_name, stcp_tx, rid, cfg, work_conn_tls, swcp).await;
                                    });
                                    self.visitor_manager
                                        .register_visitor_task(visitor.name.clone(), handle)
                                        .await;
                                }
                                _ => {}
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
                // 热重载（管理端 /reload、SIGHUP、配置文件变更）
                _ = reload_notify.notified() => {
                    reload_requested = true;
                }
                _ = sighup.recv() => {
                    log::info!("Received SIGHUP, triggering config reload...");
                    reload_requested = true;
                }
                // 管理端 POST /stop（`frpc stop`）
                _ = stop_notify.notified() => {
                    log::info!("Received stop request from admin API, shutting down gracefully...");
                    self.graceful_shutdown().await?;
                    break;
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

            if reload_requested {
                reload_requested = false;
                log::info!("Reloading config...");
                // reload_config 会重读配置并重新 add 代理/访客；随后走下方的
                // clear 重连路径按新配置整体重新注册，保证已删除的代理被下线
                if let Err(e) = self.reload_config().await {
                    log::error!("Reload config failed: {}", e);
                }
            } else {
                // 重连逻辑：登录失败与连接断开一致，均按退避重试（不退出进程），
                // 避免服务端暂时不可达时 frpc 直接死亡（信号分支自行 break）
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

                // 下次延迟：首次(0)后从 1s 起步翻倍，封顶 15s
                // （上限下调自 30s：开机/断网恢复后更快自愈，缩短 STCP 不可用窗口）
                // （修复原实现 0*2=0 导致退避永不生效的问题）
                reconnect_delay_ms = if reconnect_delay_ms == 0 {
                    1_000
                } else {
                    (reconnect_delay_ms * 2).min(max_reconnect_delay_ms)
                };
            }

            // 重置代理管理器状态
            self.proxy_manager.clear().await;
            self.visitor_manager.clear().await;
        }

        log::info!("Client shutdown completed");
        Ok(())
    }

    pub(super) async fn graceful_shutdown(&mut self) -> Result<(), Box<dyn std::error::Error>> {
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

    pub(super) async fn register_proxy(
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

    pub(super) async fn login(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 根据传输协议选择连接方式
        let protocol = self.config.transport.protocol.as_str();
        let use_tls = self
            .config
            .transport
            .tls
            .as_ref()
            .map(|t| t.enable)
            .unwrap_or(true);

        let (raw_conn, session): (ControlIo, Option<Arc<dyn Session>>) = match protocol {
            "kcp" => {
                let kcp_conn = self
                    .connector
                    .connect_kcp()
                    .await
                    .map_err(|e| format!("KCP connection failed: {}", e))?;
                (Box::new(kcp_conn), None)
            }
            "quic" => {
                // QUIC：单个 QUIC 连接内多路复用，控制连接 = 首条双向流，
                // 后续工作连接为同一连接上的新流（QUIC 自带 TLS 1.3）
                let session: Arc<dyn Session> = self
                    .connector
                    .connect_quic()
                    .await
                    .map_err(|e| format!("QUIC connection failed: {}", e))?;
                let control_stream = session
                    .open_stream()
                    .await
                    .map_err(|e| format!("QUIC open control stream failed: {}", e))?;
                log::info!("QUIC control stream established");
                (control_stream, Some(session))
            }
            "websocket" | "wss" => {
                // WebSocket 传输：TCP →（wss 时叠加 TLS）→ WebSocket 升级（路径 /~!frp）
                let host = self.config.server_addr.clone();
                let port = self.config.server_port;
                let addr = resolve_server_addr(&host, port).await?;
                let tcp = tokio::net::TcpStream::connect(addr)
                    .await
                    .map_err(|e| format!("WebSocket TCP connect to {host}:{port} failed: {e}"))?;

                let ws_conn: rust_frp_net::WebSocketConn<rust_frp_net::AnyConn> =
                    if protocol == "wss" {
                        // wss 语义即为「TLS + WebSocket」：TLS 强制开启
                        let tls_config = build_client_tls_config(&self.config)
                            .map_err(|e| format!("failed to build client TLS config: {e}"))?
                            .ok_or(
                                "protocol = \"wss\" requires TLS: configure [transport.tls] with \
                                 trusted_ca_file (pin server CA) or skip_verify = true",
                            )?;
                        let tls_stream = tls_config
                            .connect(&host, tcp)
                            .await
                            .map_err(|e| format!("wss TLS handshake failed: {e}"))?;
                        let url = format!("wss://{host}:{port}{}", rust_frp_net::FRP_WS_PATH);
                        rust_frp_net::client_websocket_stream(
                            Box::new(tls_stream) as rust_frp_net::AnyConn,
                            &url,
                            addr,
                        )
                        .await
                        .map_err(|e| format!("wss WebSocket handshake failed: {e}"))?
                    } else {
                        let url = format!("ws://{host}:{port}{}", rust_frp_net::FRP_WS_PATH);
                        rust_frp_net::client_websocket_stream(
                            Box::new(tcp) as rust_frp_net::AnyConn,
                            &url,
                            addr,
                        )
                        .await
                        .map_err(|e| format!("WebSocket handshake failed: {e}"))?
                    };
                log::info!("WebSocket control connection established ({protocol})");
                (Box::new(ws_conn), None)
            }
            _ if self.config.transport.tcp_mux => {
                // tcp_mux：TCP → magic 字节 → (TLS) → yamux 会话 → 首条流为控制流
                //（仅 TCP 协议生效，与 frp 原版语义一致）
                let addr = format!("{}:{}", self.config.server_addr, self.config.server_port)
                    .parse::<SocketAddr>()?;
                let mut tcp = tokio::net::TcpStream::connect(addr)
                    .await
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

                let session: Arc<dyn Session> = MuxSession::new_client(io);
                // 首条流 = 控制流（服务端 accept 后作为控制连接处理）
                let control_stream = session
                    .open_stream()
                    .await
                    .map_err(|e| format!("mux open control stream failed: {}", e))?;
                (control_stream, Some(session))
            }
            _ => {
                // 默认使用 TCP (可能带 TLS)
                if use_tls {
                    let tls_conn = self
                        .connector
                        .connect_tls(&self.config.server_addr)
                        .await
                        .map_err(|e| format!("TLS connection failed: {}", e))?;
                    (Box::new(tls_conn), None)
                } else {
                    let tcp_conn = self
                        .connector
                        .connect()
                        .await
                        .map_err(|e| format!("TCP connection failed: {}", e))?;
                    (Box::new(tcp_conn), None)
                }
            }
        };

        // wire protocol v2：写魔数 → ClientHello/ServerHello 能力协商 →
        // 以方向性 AEAD（HKDF 从 SHA-256(token) 派生）包装控制通道；
        // 之后的 Login 及全部控制消息均在加密通道内以 v2 帧承载。
        let mut conn: ControlConn = if self.config.transport.wire_protocol == "v2" {
            let base_key = self.auth_manager.encryption_key().ok_or(
                "transport.wire_protocol = \"v2\" requires a token: the v2 control \
                 channel derives its AEAD keys from SHA-256(token)",
            )?;
            let bootstrap = rust_frp_net::wire_v2::BootstrapInfo {
                transport: protocol.to_string(),
                tls: matches!(protocol, "wss" | "quic") || use_tls,
                tcp_mux: self.config.transport.tcp_mux,
            };
            let encrypted = rust_frp_net::wire_v2::client_handshake(raw_conn, base_key, bootstrap)
                .await
                .map_err(|e| format!("wire v2 handshake failed: {e}"))?;
            log::info!("wire protocol v2 negotiated with server");
            ControlConn::new_v2(Box::new(encrypted))
        } else {
            ControlConn::new(raw_conn)
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
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: get_timestamp(),
            run_id: run_id.clone(),
            // token 认证 → 静态令牌；oidc 认证 → 向 IdP 现取 access_token
            token: resolve_auth_token(&self.config).await?,
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
                let work_conn_tls = login_resp_msg.work_conn_tls;
                if work_conn_tls {
                    log::info!("Server negotiated TLS for work connections");
                }
                // 服务器下发的工作连接端口（0 = 旧版服务端未下发）
                let server_work_conn_port = login_resp_msg.work_conn_port;
                if server_work_conn_port > 0 {
                    log::info!(
                        "Server advertised work conn port: {}",
                        server_work_conn_port
                    );
                }
                let control = ClientControl::new(ClientControlDeps {
                    conn,
                    run_id: login_resp_msg.run_id,
                    proxy_manager: Arc::clone(&self.proxy_manager),
                    visitor_manager: Arc::clone(&self.visitor_manager),
                    auth_manager: Arc::clone(&self.auth_manager),
                    work_conn_manager: Arc::clone(&self.work_conn_manager),
                    config: Arc::clone(&self.config),
                    work_conn_tls,
                    server_work_conn_port,
                    session,
                });
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

    /// 外部触发一次配置热重载（SIGHUP/配置文件监听与管理端 /reload 共用通道）
    pub fn notify_reload(&self) {
        self.reload_notify.notify_one();
    }

    pub async fn reload_config(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(config_path) = &self.config_path {
            let mut new_config = rust_frp_config::ConfigLoader::load_client_config(config_path)?;
            // tokenSource 需在替换配置前重新解析（配置里 token 通常为空）
            apply_token_source(&mut new_config).map_err(|e| e.to_string())?;
            // 热重载不得重置 client_id：文件未写时沿用当前生效值 —— 否则会退回
            // None 并在登录时退化为主机名（多机同名 → 服务端误判重连 → 互踢）；
            // 也不能重新随机，否则服务端会视作新客户端并与旧会话抢占同名代理。
            let stable_client_id = self.config.client_id.clone();
            ensure_client_id(&mut new_config, stable_client_id.as_deref());
            self.config = Arc::new(new_config);

            // 重新启动所有代理
            for proxy in &self.config.proxies {
                self.proxy_manager
                    .add_proxy(proxy.clone())
                    .await
                    .map_err(|e| e.to_string())?;
            }

            // 先拆旧访问者任务并等它们真正退出（释放本地监听端口），再按新配置
            // 重建。少了这一步，新任务 spawn 时旧的 listener 还占着端口，只能靠
            // bind 的 1s 重试兜底——重载期间 9311/8080 会出现可见空窗，日志还会被
            // AddrInUse 刷屏（2026-10-27 现场：一次保存触发 5 次重载，通道全灭）。
            self.visitor_manager.clear().await;

            // 重新启动所有访问者
            for visitor in &self.config.visitors {
                self.visitor_manager
                    .add_visitor(visitor.clone())
                    .await
                    .map_err(|e| e.to_string())?;
            }

            // 重新启动健康检查（start_health_checks 需要 &mut self，先取出列表）
            self.stop_health_checks().await;
            let proxies = self.config.proxies.clone();
            self.start_health_checks(&proxies).await;

            log::info!("config reloaded successfully");
        }
        Ok(())
    }
}

// 注意：Client 不实现 Clone——Connector::new 依赖配置构造 TLS 连接管理器，可能失败，
// 而 Clone 无法传播错误（旧实现里 unwrap 会 panic）。全仓库也没有克隆 Client 的需求。
