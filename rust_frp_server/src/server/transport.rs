//! Server 的 transport 相关实现（原 server.rs 的 `impl Server` 片段）。

use super::*;

impl Server {
    /// 处理多路复用控制连接（tcp_mux 客户端）
    ///
    /// 连接结构：TLS（如启用）→ yamux 会话；首条流为控制流，
    /// 后续流为工作连接（与 work listener 共用 process_work_conn，协议零变更）。
    /// 控制流退出 → 关闭整个会话（分发循环随之结束）。
    pub(super) async fn handle_mux_connection(
        conn: tokio::net::TcpStream,
        managers: ServerManagers,
        tls_config: Option<TlsConfig>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let ServerManagers {
            control_manager,
            proxy_manager,
            visitor_manager,
            auth_runtime,
            proxy_owners,
            xtcp_visitors,
            stcp_bridge_manager,
            work_conn_manager,
            plugin_manager,
            work_conn_port,
        } = managers;
        let auth_manager = auth_runtime.read().await.clone();
        // 工作连接 TLS 协商标志（mux 下工作连接为会话流，TLS 在会话层；
        // 保持与 LoginResp 协商一致性）
        let work_conn_tls = tls_config.is_some();

        // P4：mTLS 客户端证书指纹（无 TLS / 客户端未出示证书时保持 None）
        let mut peer_cert_fingerprint: Option<String> = None;
        let io: AnyConn = if let Some(tls_config) = tls_config {
            let tls_stream = match tls_config.accept(conn).await {
                Ok(s) => s,
                Err(e) => {
                    global_metrics().incr_tls_rejects();
                    log::warn!("TLS accept failed (mux): {}", e);
                    return Err(format!("TLS accept failed: {}", e).into());
                }
            };
            peer_cert_fingerprint = peer_cert_fingerprint_of(&tls_stream);
            match &peer_cert_fingerprint {
                Some(fp) => log::info!("client certificate fingerprint (mux): {}", short_fp(fp)),
                None => log::debug!("no client certificate presented on mux control connection"),
            }
            Box::new(tls_stream)
        } else {
            Box::new(conn)
        };

        let session = MuxSession::new_server(io);

        // 首条流 = 控制流
        let control_stream = session.accept_stream().await?;
        // 分发循环所需的克隆（spawn_control 会移走原值）
        let sbm = stcp_bridge_manager.clone();
        let cm = control_manager.clone();
        let wcm = work_conn_manager.clone();
        let pm = plugin_manager.clone();
        let control = Self::negotiate_control_conn(control_stream, &auth_manager).await?;
        let control_handle = Self::spawn_control(
            control,
            ServerManagers {
                control_manager,
                proxy_manager,
                visitor_manager,
                auth_runtime,
                proxy_owners,
                xtcp_visitors,
                stcp_bridge_manager,
                work_conn_manager,
                plugin_manager,
                work_conn_port,
            },
            auth_manager,
            work_conn_tls,
            None,
            peer_cert_fingerprint,
            false,
        );

        // 后续流 = 工作连接，逐条分发
        let dispatch_session = session.clone();
        let dispatch = tokio::spawn(async move {
            while let Ok(stream) = dispatch_session.accept_stream().await {
                log::info!("New mux work stream");
                let cm = cm.clone();
                let wcm = wcm.clone();
                let sbm = sbm.clone();
                let pm = pm.clone();
                tokio::spawn(async move {
                    if let Err(e) = Server::process_work_conn(stream, cm, wcm, sbm, pm).await {
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

    pub(super) async fn handle_kcp_connection(
        kcp_conn: KcpConn,
        managers: ServerManagers,
        work_conn_tls: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let ServerManagers {
            control_manager,
            proxy_manager,
            auth_runtime,
            proxy_owners,
            xtcp_visitors,
            stcp_bridge_manager,
            work_conn_manager,
            plugin_manager,
            work_conn_port,
            ..
        } = managers;
        let auth_manager = auth_runtime.read().await.clone();
        let conn = Self::negotiate_control_conn(Box::new(kcp_conn), &auth_manager).await?;

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
            work_conn_port,
            pre_read_login: None,
            plugin_manager,
            // KCP 是 UDP 明文传输，没有 TLS 握手 ⇒ 无客户端证书指纹。
            // 该路径下会话接管仍按 client_id 判定（文档已标注该传输不受 mTLS 保护）。
            peer_cert_fingerprint: None,
        });

        let msg_tx_clone = control.msg_tx.clone();

        tokio::spawn(async move {
            // 优雅关闭排空：KCP 控制会话存活期间保持全局连接计数
            let _drain_guard = global_metrics().connection_guard();
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

    /// 处理一条 QUIC 连接：在该连接上循环接受双向流，逐条分派
    pub(super) async fn handle_quic_connection(conn: QuicConnection, managers: ServerManagers) {
        let remote = conn.remote_addr();
        loop {
            match conn.accept_stream().await {
                Ok(stream) => {
                    let managers = managers.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_quic_stream(stream, managers).await {
                            log::debug!("QUIC stream from {} ended: {:?}", remote, e);
                        }
                    });
                }
                Err(e) => {
                    log::debug!("QUIC connection from {} closed: {:?}", remote, e);
                    break;
                }
            }
        }
    }

    /// 处理一条 QUIC 双向流：按首条消息分派到控制连接或工作连接路径
    ///
    /// QUIC 在单条连接上复用多条流，服务端无法像 TCP 那样按端口区分控制/工作
    /// 连接，因此读取首条消息后分派（`Login` → 控制，`NewWorkConn` → 工作连接）。
    pub(super) async fn handle_quic_stream(
        stream: rust_frp_net::QuicConn,
        managers: ServerManagers,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let auth_manager = managers.auth_runtime.read().await.clone();
        // wire protocol v2 协商（非 v2 时原样回放嗅探字节，保持 v1 路径零变更）
        let mut conn = Self::negotiate_control_conn(Box::new(stream), &auth_manager).await?;

        // 安全：首帧读取受认证前超时与大小上限约束（P0-1 / P0-2）
        let msg = match tokio::time::timeout(
            LOGIN_READ_TIMEOUT,
            conn.read_message_with_limit(rust_frp_core::MAX_PREAUTH_MESSAGE_SIZE),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                log::warn!(
                    "QUIC stream first message timed out after {:?}",
                    LOGIN_READ_TIMEOUT
                );
                return Err("QUIC stream handshake timeout".into());
            }
        };

        match msg {
            Message::Login(login) => {
                // QUIC 自带 TLS 1.3：工作连接复用同连接的新流，无需再协商 work_conn_tls
                // P4 已知缺口：此处只拿到单条流（`QuicConn`），拿不到连接对象 ⇒ 无法读取
                // 对端证书指纹，故传 None，该路径下会话接管仍按 client_id 判定。
                // 线上 `transport.protocol = "tcp"`，未使用 QUIC；若将来启用 QUIC + mTLS，
                // 需把 `quinn::Connection` 一并传进来补齐（见设计稿 §5 注）。
                Self::spawn_control(
                    conn,
                    managers,
                    auth_manager,
                    false,
                    Some(login),
                    None,
                    false,
                );
                Ok(())
            }
            m @ Message::NewWorkConn(_) => {
                // 分派到工作连接路径：放弃控制帧语义，按原始流处理
                let raw: AnyConn = conn.into_inner();
                let ServerManagers {
                    control_manager,
                    work_conn_manager,
                    stcp_bridge_manager,
                    plugin_manager,
                    ..
                } = managers;
                Self::process_work_conn_msg(
                    raw,
                    m,
                    control_manager,
                    work_conn_manager,
                    stcp_bridge_manager,
                    plugin_manager,
                )
                .await
            }
            other => {
                log::warn!("Unexpected first message on QUIC stream: {:?}", other);
                Err("unexpected first message on QUIC stream".into())
            }
        }
    }
}
