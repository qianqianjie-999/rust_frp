//! Server 的 work_conn 相关实现（原 server.rs 的 `impl Server` 片段）。

use super::*;

impl Server {
    /// 处理工作连接（支持 TLS/明文混跑 + tls_only 强制）
    pub(super) async fn handle_work_connections(
        listener: std::sync::Arc<tokio::net::TcpListener>,
        managers: ServerManagers,
        tls_config: Option<TlsConfig>,
        tls_only: bool,
        keepalive: Option<std::time::Duration>,
    ) {
        let ServerManagers {
            control_manager,
            work_conn_manager,
            stcp_bridge_manager,
            plugin_manager,
            ..
        } = managers;
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
                    // 工作连接常被连接池预建后长期空闲；在 TLS 包装之前对底层
                    // TCP 开启 keepalive，让内核负责 NAT 表项续期与死连接探测。
                    if let Some(idle) = keepalive {
                        if let Err(e) = rust_frp_net::apply_tcp_keepalive(&conn, idle) {
                            log::debug!(
                                "set TCP keepalive on work conn from {:?} failed: {}",
                                addr,
                                e
                            );
                        }
                    }
                    let cm = control_manager.clone();
                    let wcm = work_conn_manager.clone();
                    let sbm = stcp_bridge_manager.clone();
                    let pm = plugin_manager.clone();
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
                                // classify_work_conn 仅在 tls_available=true 时返回 Tls，
                                // 此处必然为 Some；若违反则按拒绝处理而非 panic
                                let tls_config = match tls_config {
                                    Some(c) => c,
                                    None => {
                                        global_metrics().incr_tls_rejects();
                                        log::warn!(
                                            "TLS work conn from {:?} but no TLS config (unexpected), rejected",
                                            addr
                                        );
                                        let _ = conn.shutdown().await;
                                        return;
                                    }
                                };
                                log::info!("New TLS work connection from: {:?}", addr);
                                match tls_config.accept(conn).await {
                                    Ok(tls_stream) => {
                                        if let Err(e) = Self::process_work_conn(
                                            Box::new(tls_stream),
                                            cm,
                                            wcm,
                                            sbm,
                                            pm,
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
                                    Self::process_work_conn(Box::new(conn), cm, wcm, sbm, pm).await
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

    /// 处理单个工作连接（TCP / TLS 直连工作端口）：读取首消息后交给共用处理逻辑
    pub(super) async fn process_work_conn(
        mut conn: AnyConn,
        control_manager: Arc<ControlManager>,
        work_conn_manager: Arc<ServerWorkConnManager>,
        stcp_bridge_manager: Arc<StcpBridgeManager>,
        plugin_manager: Arc<rust_frp_plugin::server_plugin::Manager>,
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
        Self::process_work_conn_msg(
            conn,
            msg,
            control_manager,
            work_conn_manager,
            stcp_bridge_manager,
            plugin_manager,
        )
        .await
    }

    /// 处理一条已完成首消息读取的工作连接（TCP / TLS / QUIC 流共用）
    pub(super) async fn process_work_conn_msg(
        mut conn: AnyConn,
        msg: Message,
        control_manager: Arc<ControlManager>,
        work_conn_manager: Arc<ServerWorkConnManager>,
        stcp_bridge_manager: Arc<StcpBridgeManager>,
        plugin_manager: Arc<rust_frp_plugin::server_plugin::Manager>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
                let Some(auth_manager) = control_manager.get_auth_manager(&work_msg.run_id).await
                else {
                    log::error!("No authentication snapshot for run_id {}", work_msg.run_id);
                    let resp = Message::StartWorkConn(rust_frp_core::StartWorkConnMsg {
                        error: "Session authentication unavailable".to_string(),
                        src_addr: String::new(),
                        src_port: 0,
                        dst_addr: String::new(),
                        dst_port: 0,
                    });
                    write_message_with_timeout(&mut conn, &resp).await?;
                    return Err("Session authentication unavailable".into());
                };

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

                // 服务端插件回调：NewWorkConn（可拒绝该工作连接）
                let work_user = control_manager
                    .get_user_by_run_id(&work_msg.run_id)
                    .await
                    .unwrap_or_default();
                let mut plugin_content = serde_json::json!({
                    "user": {
                        "user": work_user,
                        "run_id": work_msg.run_id,
                        "metas": {},
                    },
                    "proxy_name": work_msg.proxy_name.clone(),
                    "run_id": work_msg.run_id.clone(),
                    "timestamp": work_msg.timestamp,
                });
                if let Err(reason) = plugin_manager.new_work_conn(&mut plugin_content).await {
                    log::warn!(
                        "Work conn for proxy [{}] rejected by http plugin: {}",
                        work_msg.proxy_name,
                        reason
                    );
                    let resp = Message::StartWorkConn(rust_frp_core::StartWorkConnMsg {
                        error: format!("work conn rejected by plugin: {}", reason),
                        src_addr: String::new(),
                        src_port: 0,
                        dst_addr: String::new(),
                        dst_port: 0,
                    });
                    write_message_with_timeout(&mut conn, &resp).await?;
                    return Err("work conn rejected by plugin".into());
                }

                // 应用层加密 fail-closed 预检：客户端请求加密但服务端未配 token 时，
                // 以明文 StartWorkConn(error) 拒绝（此刻连接尚未包装，可以明文写）
                if work_msg.use_encryption && auth_manager.encryption_key().is_none() {
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

                if work_msg.bridge_id.is_empty() {
                    work_conn_manager
                        .register_work_conn(
                            &work_msg.proxy_name,
                            conn,
                            work_msg.use_compression,
                            work_msg.use_encryption,
                            auth_manager.encryption_key().map(|key| key.to_vec()),
                        )
                        .await;
                    return Ok(());
                }

                let role = match stcp_bridge_manager
                    .reserve_leg(
                        &work_msg.bridge_id,
                        &work_msg.run_id,
                        &work_msg.bridge_sign_key,
                    )
                    .await
                {
                    Ok(role) => role,
                    Err(reason) => {
                        log::warn!(
                            "Rejected STCP bridge leg {} for {}: {}",
                            work_msg.bridge_id,
                            work_msg.proxy_name,
                            reason
                        );
                        let resp = Message::StartWorkConn(rust_frp_core::StartWorkConnMsg {
                            error: reason.to_string(),
                            src_addr: String::new(),
                            src_port: 0,
                            dst_addr: String::new(),
                            dst_port: 0,
                        });
                        write_message_with_timeout(&mut conn, &resp).await?;
                        return Err(reason.into());
                    }
                };

                let resp = Message::StartWorkConn(rust_frp_core::StartWorkConnMsg {
                    error: String::new(),
                    src_addr: String::new(),
                    src_port: 0,
                    dst_addr: String::new(),
                    dst_port: 0,
                });
                if let Err(e) = write_message_with_timeout(&mut conn, &resp).await {
                    stcp_bridge_manager
                        .release_leg(&work_msg.bridge_id, role)
                        .await;
                    return Err(e);
                }

                let mut conn: AnyConn = conn;
                if work_msg.use_compression {
                    log::info!(
                        "Work conn compression (snappy) enabled for proxy: {}",
                        work_msg.proxy_name
                    );
                    conn = Box::new(rust_frp_net::compress::CompressedStream::new(conn));
                }
                if work_msg.use_encryption {
                    if let Some(key) = auth_manager.encryption_key() {
                        conn = Box::new(rust_frp_net::crypto::EncryptedStream::new(conn, key)?);
                    }
                }

                match stcp_bridge_manager
                    .install_leg(&work_msg.bridge_id, role, conn)
                    .await
                {
                    Ok(Some((owner, visitor))) => {
                        log::info!(
                            "STCP bridge {} ready for {}, bridging",
                            work_msg.bridge_id,
                            work_msg.proxy_name
                        );
                        let proxy_name = work_msg.proxy_name.clone();
                        tokio::spawn(async move {
                            let _drain_guard = global_metrics().connection_guard();
                            match rust_frp_util::bridge_streams_counted(owner, visitor).await {
                                Ok((to_owner, to_visitor)) => {
                                    global_metrics().record_traffic(
                                        &proxy_name,
                                        to_owner,
                                        to_visitor,
                                    );
                                }
                                Err(e) => rust_frp_util::log_bridge_error(
                                    &format!("STCP bridge error for {proxy_name}"),
                                    e.as_ref(),
                                ),
                            }
                        });
                    }
                    Ok(None) => {}
                    Err(_conn) => {
                        return Err(format!(
                            "STCP bridge {} disappeared while installing leg",
                            work_msg.bridge_id
                        )
                        .into());
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
}
