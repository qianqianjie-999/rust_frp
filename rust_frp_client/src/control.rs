//! 从 lib.rs 拆出的 control 实现。

use super::*;

/// 客户端控制
// 部分通道字段（udp_resp_rx 等）由消息循环按需消费，整结构保留以便协议扩展
#[allow(dead_code)]
pub struct ClientControl {
    pub conn: ControlConn,
    pub(super) run_id: String,
    pub(super) proxy_manager: Arc<ClientProxyManager>,
    pub(super) visitor_manager: Arc<ClientVisitorManager>,
    pub(super) auth_manager: Arc<AuthManager>,
    pub(super) work_conn_manager: Arc<WorkConnManager>,
    pub(super) config: Arc<ClientConfig>,
    pub(super) udp_sockets: RwLock<std::collections::HashMap<String, Arc<tokio::net::UdpSocket>>>,
    pub(super) udp_resp_tx: tokio::sync::mpsc::Sender<Message>,
    pub(super) udp_resp_rx: tokio::sync::mpsc::Receiver<Message>,
    pub(super) stcp_visitor_tx: tokio::sync::mpsc::Sender<Message>,
    pub(super) stcp_visitor_rx: tokio::sync::mpsc::Receiver<Message>,
    pub(super) last_pong_time: std::time::Instant,
    /// 服务端通过 HTTP 插件拒绝了心跳（Pong 带 error），需要重连
    pub(super) plugin_rejected_heartbeat: bool,
    /// 工作连接是否使用 TLS（来自服务器 LoginRespMsg.work_conn_tls 协商）
    pub(super) work_conn_tls: bool,
    /// 服务器下发的工作连接端口（0 = 旧版服务端未下发，按本地推算）
    pub(super) server_work_conn_port: u16,
    /// 多路复用会话：tcp_mux 的 yamux 会话，或 QUIC 连接
    ///
    /// 存在时工作连接不再新建底层连接，而是从会话打开新流；
    /// tcp_mux 的 TLS 在会话层（底层 TCP 已含），QUIC 则由协议内建 TLS 1.3。
    pub(super) session: Option<Arc<dyn Session>>,
    /// XTCP 打洞会话注册表（visitor 等待 owner NAT 信息）
    pub(super) xtcp_registry: Arc<XtcpRegistry>,
}

/// 登录成功后构造控制会话所需的依赖集合（收敛 9 个独立参数，避免参数顺序误用）
pub struct ClientControlDeps {
    pub conn: ControlConn,
    pub run_id: String,
    pub proxy_manager: Arc<ClientProxyManager>,
    pub visitor_manager: Arc<ClientVisitorManager>,
    pub auth_manager: Arc<AuthManager>,
    pub work_conn_manager: Arc<WorkConnManager>,
    pub config: Arc<ClientConfig>,
    pub work_conn_tls: bool,
    /// 服务器 LoginResp 下发的工作连接端口（0 = 未下发）
    pub server_work_conn_port: u16,
    pub session: Option<Arc<dyn Session>>,
}

impl ClientControl {
    pub fn new(deps: ClientControlDeps) -> Self {
        let ClientControlDeps {
            conn,
            run_id,
            proxy_manager,
            visitor_manager,
            auth_manager,
            work_conn_manager,
            config,
            work_conn_tls,
            server_work_conn_port,
            session,
        } = deps;
        let (tx, rx) = tokio::sync::mpsc::channel::<Message>(256);
        let (stcp_tx, stcp_rx) = tokio::sync::mpsc::channel::<Message>(100);
        Self {
            conn,
            run_id,
            proxy_manager,
            visitor_manager,
            auth_manager,
            work_conn_manager,
            config,
            udp_sockets: RwLock::new(std::collections::HashMap::new()),
            udp_resp_tx: tx,
            udp_resp_rx: rx,
            stcp_visitor_tx: stcp_tx,
            stcp_visitor_rx: stcp_rx,
            last_pong_time: std::time::Instant::now(),
            plugin_rejected_heartbeat: false,
            work_conn_tls,
            server_work_conn_port,
            session,
            xtcp_registry: Arc::new(XtcpRegistry::default()),
        }
    }

    pub fn stcp_visitor_sender(&self) -> tokio::sync::mpsc::Sender<Message> {
        self.stcp_visitor_tx.clone()
    }

    /// XTCP 打洞会话注册表
    pub(super) fn xtcp_registry(&self) -> Arc<XtcpRegistry> {
        self.xtcp_registry.clone()
    }

    /// 工作连接是否需要 TLS（服务器 LoginRespMsg.work_conn_tls 协商结果）
    pub fn work_conn_tls(&self) -> bool {
        self.work_conn_tls
    }

    /// 服务器下发的工作连接端口（0 = 旧版服务端未下发，按本地推算）
    pub fn server_work_conn_port(&self) -> u16 {
        self.server_work_conn_port
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut msg_count = 0u32;
        // 心跳 10 秒一次（配合 Nginx proxy_read_timeout 300s 绰绰有余；
        // 断线时最多 20 秒就能发现：10s 没收到 pong → 触发下一次 ping → 发现写失败）
        let heartbeat_interval_secs: u64 = 10;
        let mut last_ping_time = std::time::Instant::now();

        log::debug!("ClientControl::run started, waiting for messages...");

        loop {
            // 定期发送 ping 消息
            if last_ping_time.elapsed() > std::time::Duration::from_secs(heartbeat_interval_secs) {
                let timestamp = get_timestamp();
                // additionalScopes 含 heartBeats 时附带 HMAC 签名（未启用则为空串）
                let ping_msg = rust_frp_core::PingMsg {
                    timestamp,
                    privilege_key: self
                        .auth_manager
                        .ping_privilege_key(timestamp)
                        .unwrap_or_default(),
                };
                log::debug!("Sending ping message, count: {}", msg_count);
                if let Err(e) = self.conn.write_message(&Message::Ping(ping_msg)).await {
                    log::error!("Failed to send ping (connection lost): {:?}", e);
                    break;
                }
                last_ping_time = std::time::Instant::now();
            }

            log::debug!("Waiting for message, count: {}", msg_count);

            tokio::select! {
                msg_result = tokio::time::timeout(std::time::Duration::from_secs(15), self.conn.read_message()) => {
                    match msg_result {
                        Ok(Ok(msg)) => {
                            msg_count += 1;
                            log::debug!("成功读取消息, 计数: {}", msg_count);
                            self.handle_message(msg).await;
                            if self.plugin_rejected_heartbeat {
                                log::warn!(
                                    "Server rejected heartbeat via plugin, reconnecting..."
                                );
                                break;
                            }
                        }
                        Ok(Err(e)) => {
                            log::error!("Failed to read message from connection: {:?}", e);
                            break;
                        }
                        Err(_elapsed) => {
                            if self.last_pong_time.elapsed() > std::time::Duration::from_secs(90) {
                                log::warn!(
                                    "Heartbeat timeout (no pong for {:?}), connection dead, reconnecting...",
                                    self.last_pong_time.elapsed()
                                );
                                break;
                            }
                        }
                    }
                }
                udp_msg = self.udp_resp_rx.recv() => {
                    if let Some(msg) = udp_msg {
                        log::debug!("Sending UDP response to server");
                        if let Err(e) = self.conn.write_message(&msg).await {
                            log::error!("Failed to send UDP response: {:?}", e);
                        }
                    }
                }
                msg = self.stcp_visitor_rx.recv() => {
                    if let Some(msg) = msg {
                        log::debug!("Sending STCP visitor message to server");
                        if let Err(e) = self.conn.write_message(&msg).await {
                            log::error!("Failed to send STCP visitor message: {:?}", e);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// 处理消息的通用方法
    pub(super) async fn handle_message(&mut self, msg: Message) {
        match msg {
            Message::Pong(pong_msg) => {
                self.last_pong_time = std::time::Instant::now();
                if !pong_msg.error.is_empty() {
                    // 服务端 HTTP 插件拒绝了本次心跳：本会话不再被认可，触发重连
                    log::error!(
                        "Server rejected heartbeat via plugin: {}; reconnecting",
                        pong_msg.error
                    );
                    self.plugin_rejected_heartbeat = true;
                }
                log::debug!("收到 Pong 消息: timestamp={}", pong_msg.timestamp);
            }
            Message::StcpVisitorResp(resp) => {
                // STCP 访问端桥就绪确认：成功唤醒等待者，失败则让其报错返回
                let result = if resp.error.is_empty() {
                    Ok(StcpVisitorGrant {
                        bridge_id: resp.bridge_id.clone(),
                        work_conn_sign_key: resp.work_conn_sign_key.clone(),
                    })
                } else {
                    Err(resp.error.clone())
                };
                log::info!(
                    "Received StcpVisitorResp for proxy {}: {}",
                    resp.proxy_name,
                    if resp.error.is_empty() {
                        "ok"
                    } else {
                        &resp.error
                    }
                );
                StcpRespRegistry::global().resolve(&resp.bridge_id, result);
            }
            Message::ReqWorkConn(req_work_conn_msg) => {
                // 服务器请求建立工作连接
                log::debug!(
                    "收到 ReqWorkConn 消息: proxy={}",
                    req_work_conn_msg.proxy_name
                );
                log::info!(
                    "Received ReqWorkConn for proxy: {}",
                    req_work_conn_msg.proxy_name
                );
                let proxy_name = req_work_conn_msg.proxy_name.clone();
                let bridge_id = req_work_conn_msg.bridge_id.clone();
                let bridge_sign_key = req_work_conn_msg.work_conn_sign_key.clone();
                let run_id = self.run_id.clone();
                let config = Arc::clone(&self.config);
                let work_conn_tls = self.work_conn_tls;
                let server_work_conn_port = self.server_work_conn_port;
                let session = self.session.clone();

                tokio::spawn(async move {
                    log::debug!("开始建立工作连接: proxy={}", proxy_name);
                    if let Err(e) = establish_work_connection(
                        &config,
                        WorkConnEstablishRequest {
                            proxy_name: &proxy_name,
                            run_id: &run_id,
                            bridge_id: &bridge_id,
                            bridge_sign_key: &bridge_sign_key,
                            work_conn_tls,
                            server_work_conn_port,
                            session: session.as_ref(),
                        },
                    )
                    .await
                    {
                        if work_conn_disconnect_is_retryable(&e.to_string()) {
                            log::debug!(
                                "Work connection for {} closed during setup (retryable): {:?}",
                                proxy_name,
                                e
                            );
                        } else {
                            log::error!(
                                "Failed to establish work connection for {}: {:?}",
                                proxy_name,
                                e
                            );
                        }
                    } else {
                        log::debug!("工作连接建立成功: proxy={}", proxy_name);
                    }
                });
            }
            Message::UdpPacket(udp_msg) => {
                let proxy_name = udp_msg.proxy_name;
                let data = udp_msg.data;
                let client_addr = udp_msg.client_addr.clone();

                let proxy_config = self
                    .config
                    .proxies
                    .iter()
                    .find(|p| p.name == proxy_name)
                    .cloned();

                if let Some(cfg) = proxy_config {
                    let local_addr = format!("{}:{}", cfg.local_ip, cfg.local_port);

                    let socket = {
                        let mut sockets = self.udp_sockets.write().await;
                        if let Some(s) = sockets.get(&proxy_name) {
                            s.clone()
                        } else {
                            match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                                Ok(s) => {
                                    let s = Arc::new(s);
                                    sockets.insert(proxy_name.clone(), s.clone());
                                    s
                                }
                                Err(e) => {
                                    log::error!(
                                        "Failed to bind UDP socket for proxy {}: {:?}",
                                        proxy_name,
                                        e
                                    );
                                    return;
                                }
                            }
                        }
                    };

                    if let Err(e) = socket.send_to(&data, &local_addr).await {
                        log::error!(
                            "Failed to send UDP data to {} for proxy {}: {:?}",
                            local_addr,
                            proxy_name,
                            e
                        );
                        return;
                    }

                    let resp_tx = self.udp_resp_tx.clone();
                    let proxy_name_clone = proxy_name.clone();
                    let client_addr_clone = client_addr.clone();
                    let socket_clone = socket.clone();
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 65535];
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            socket_clone.recv_from(&mut buf),
                        )
                        .await
                        {
                            Ok(Ok((n, _))) => {
                                let resp_data = buf[..n].to_vec();
                                let resp_msg = Message::UdpPacket(rust_frp_core::UdpPacketMsg {
                                    proxy_name: proxy_name_clone,
                                    data: resp_data,
                                    client_addr: client_addr_clone,
                                });
                                if let Err(e) = resp_tx.send(resp_msg).await {
                                    log::error!("Failed to send UDP response via channel: {:?}", e);
                                }
                            }
                            Ok(Err(e)) => {
                                log::error!(
                                    "UDP recv error for proxy {}: {:?}",
                                    proxy_name_clone,
                                    e
                                );
                            }
                            Err(_) => {
                                log::debug!("UDP response timeout for proxy {}", proxy_name_clone);
                            }
                        }
                    });
                } else {
                    log::error!("UDP proxy config not found: {}", proxy_name);
                }
            }
            Message::XtcpNatInfo(xtcp_msg) => {
                let proxy_name = xtcp_msg.proxy_name.clone();
                log::info!(
                    "Received XTCP NAT info from {} for proxy {}",
                    xtcp_msg.run_id,
                    proxy_name
                );

                // 本客户端提供该 proxy → owner 侧：回送自己的 NAT info 并启动 KCP 打洞
                if let Some(proxy_cfg) = self
                    .config
                    .proxies
                    .iter()
                    .find(|p| p.name == proxy_name)
                    .cloned()
                {
                    let tx = self.stcp_visitor_tx.clone();
                    let rid = self.run_id.clone();
                    let visitor_public = xtcp_msg.public_addr.clone();
                    let visitor_local = xtcp_msg.local_addr.clone();
                    tokio::spawn(async move {
                        run_xtcp_owner(proxy_cfg, visitor_public, visitor_local, tx, rid).await;
                    });
                } else {
                    // visitor 侧：owner 回传的 NAT info，唤醒等待打洞的连接任务
                    let resolved = self.xtcp_registry.resolve(
                        &proxy_name,
                        (xtcp_msg.public_addr.clone(), xtcp_msg.local_addr.clone()),
                    );
                    if !resolved {
                        log::debug!(
                            "XTCP NAT info for {} but no pending visitor session",
                            proxy_name
                        );
                    }
                }
            }
            Message::XtcpHolePunch(_) => {
                // KCP 打洞模式下不再使用 TCP HolePunch 消息（打洞包由 KcpStream 内置处理）
                log::debug!("ignoring legacy XtcpHolePunch message (KCP punch mode)");
            }
            _ => {
                log::warn!("unexpected message: {:?}", msg);
            }
        }
    }
}
