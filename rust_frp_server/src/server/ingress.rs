//! Server 的 ingress 相关实现（原 server.rs 的 `impl Server` 片段）。

use super::*;

impl Server {
    pub(super) async fn start_monitor_task(&self) {
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

    /// STCP 待桥接条目的定时回收：不依赖请求触发的懒清理。
    ///
    /// 起因（2026-10-28 复盘僵尸桥）：`reap_zombie_bridges` 原先只在
    /// create_bridge / reserve_leg 里被顺带调用，于是
    /// ① 没人访问的时段完全不回收，僵尸条目常驻；
    /// ② 对端集体失联时条目持续堆积，把 `MAX_PENDING_BRIDGES` 推向饱和，
    ///    满了之后所有 STCP 建桥被拒，等于整条 STCP 通路不可用。
    /// 这里每 `BRIDGE_GC_INTERVAL` 主动扫一遍，随 shutdown 一起退出。
    pub(super) async fn start_stcp_bridge_gc_task(&self) {
        let sbm = self.stcp_bridge_manager.clone();
        let shutdown = self.shutdown_notify.clone();
        tokio::spawn(async move {
            log::info!(
                "STCP bridge GC started (interval {:?})",
                crate::control::BRIDGE_GC_INTERVAL
            );
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(crate::control::BRIDGE_GC_INTERVAL) => {
                        let (reaped, replay) = sbm.sweep_stale().await;
                        if reaped > 0 || replay > 0 {
                            log::debug!(
                                "STCP bridge GC: reaped {} stale bridge(s), {} replay id(s)",
                                reaped,
                                replay
                            );
                        }
                    }
                    _ = shutdown.notified() => {
                        log::debug!("STCP bridge GC task stopped");
                        return;
                    }
                }
            }
        });
    }

    pub(super) async fn handle_tcp_connections(
        &mut self,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 监听器 take 出来：优雅关闭时随局部变量 drop 而关闭套接字，
        // 立即停止接收新连接（不再依赖进程退出强制回收）
        if let Some(listener) = self.tcp_listener.take() {
            let tls_config = match self.config.transport.tls.as_ref() {
                Some(tls) if tls.enable => Some(build_server_tls_config(tls)?),
                _ => None,
            };
            // P1：明文 ws 控制连接的准入策略（需要更强的传输保证时直接拒绝）
            let reject_plaintext_ws = plaintext_ws_must_be_rejected(
                self.config.transport.tls_only,
                self.config.transport.tls.as_ref(),
            );
            if reject_plaintext_ws {
                log::info!(
                    "Plaintext websocket control connections are rejected \
                     (tls_only = {}, require_client_cert = {})",
                    self.config.transport.tls_only,
                    self.config
                        .transport
                        .tls
                        .as_ref()
                        .map(|t| t.require_client_cert)
                        .unwrap_or(false)
                );
            }

            let mut reload_rx = self.reload_rx.take();
            let config_path = self.config_path.clone();
            let shutdown = self.shutdown_notify.clone();

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
                                    Self::handle_connection(
                                        conn,
                                        managers,
                                        tls_config,
                                        reject_plaintext_ws,
                                    )
                                    .await
                                {
                                    log::error!("handle connection error: {:?}", e);
                                }
                                metrics.decrement_connections();
                            });
                        }
                        _ = rx.recv() => {
                            log::info!("Reload signal received, reloading config...");
                            if let Err(e) = reload_server_config(&config_path, &mut self.config, &self.auth_runtime, &self.proxy_manager).await {
                                log::error!("Reload config failed: {}", e);
                            }
                        }
                        // 优雅关闭：退出 accept 循环，监听器随作用域结束关闭
                        _ = shutdown.notified() => {
                            log::info!("Shutdown signal received, accept loop stopped");
                            return Ok(());
                        }
                    }
                } else {
                    let (conn, addr) = tokio::select! {
                        result = listener.accept() => result?,
                        // 优雅关闭：退出 accept 循环
                        _ = shutdown.notified() => {
                            log::info!("Shutdown signal received, accept loop stopped");
                            return Ok(());
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
                            Self::handle_connection(conn, managers, tls_config, reject_plaintext_ws)
                                .await
                        {
                            log::error!("handle connection error: {:?}", e);
                        }
                        metrics.decrement_connections();
                    });
                }
            }
        }
        Ok(())
    }

    pub(super) async fn handle_connection(
        mut conn: tokio::net::TcpStream,
        managers: ServerManagers,
        tls_config: Option<TlsConfig>,
        reject_plaintext_ws: bool,
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
        // 首字节嗅探：TCP_MUX_MAGIC = tcp_mux 客户端（多路复用路径）；
        // "GET " = WebSocket 升级控制连接（明文 websocket 传输）。
        // 安全：入口嗅探与 TLS 握手都必须受握手超时约束（P0-1），
        // 未认证连接不允许永久占用任务。
        let mut first = [0u8; 4];
        let sniffed = tokio::time::timeout(LOGIN_READ_TIMEOUT, conn.peek(&mut first)).await;
        let sniffed_len = match sniffed {
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
            Ok(Ok(n)) => n,
        };
        // 明文 WebSocket 控制连接：先完成 Upgrade，再按控制连接处理
        if sniffed_len > 0 && is_websocket_prefix(&first[..sniffed_len]) {
            let peer = conn.peer_addr().ok();
            // P1：强制 TLS / 强制客户端证书时拒绝明文 ws ——
            // 这条路径不套 TLS，拿不到客户端证书，会让"双因素"降级成单因素 token。
            if reject_plaintext_ws {
                global_metrics().incr_tls_rejects();
                log::warn!(
                    "Rejected plaintext websocket control connection from {:?}: \
                     tls_only / require_client_cert is enabled, and this path cannot present a \
                     client certificate",
                    peer
                );
                return Err(
                    "plaintext websocket control connection rejected: TLS client certificate \
                     (mTLS) is required"
                        .into(),
                );
            }
            log::info!("websocket control connection detected from {:?}", peer);
            let ws_conn =
                rust_frp_net::accept_websocket_stream(conn, peer.unwrap_or_else(placeholder_addr))
                    .await?;
            let control = Self::negotiate_control_conn(Box::new(ws_conn), &auth_manager).await?;
            // 明文（非 wss）控制连接：无 TLS ⇒ 无客户端证书指纹
            Self::spawn_control(
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
                tls_config.is_some(),
                None,
                // 明文 WebSocket：未走 TLS 握手 ⇒ 无客户端证书指纹
                None,
                // P1 可观测性：走这条路的控制连接登录成功后要打 WARN
                true,
            );
            return Ok(());
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
                    auth_runtime,
                    proxy_owners,
                    xtcp_visitors,
                    stcp_bridge_manager,
                    work_conn_manager,
                    plugin_manager,
                    work_conn_port,
                },
                tls_config,
            )
            .await;
        }

        // 工作连接 TLS 协商标志：与控制连接共用同一 TLS 配置
        let work_conn_tls = tls_config.is_some();
        let peer = conn.peer_addr().ok().unwrap_or_else(placeholder_addr);
        // P4：mTLS 客户端证书指纹（无 TLS / 客户端未出示证书时保持 None）
        let mut peer_cert_fingerprint: Option<String> = None;
        let conn: AnyConn = if let Some(tls_config) = tls_config {
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
            // P4：握手已完成，此处的对端证书链**已经过 client_ca_file 校验**
            // （若服务端启用了 mTLS）。取其指纹用于会话接管判据。
            peer_cert_fingerprint = peer_cert_fingerprint_of(&tls_stream);
            match &peer_cert_fingerprint {
                Some(fp) => log::info!("client certificate fingerprint: {}", short_fp(fp)),
                None => log::debug!("no client certificate presented on control connection"),
            }
            // TLS 之上仍可能是 wss 的 WebSocket 升级：预读前 4 字节判定，
            // 非升级请求则原样回放给普通控制连接解析。
            let mut tls_stream = tls_stream;
            let prefix = rust_frp_net::read_prefix(&mut tls_stream, 4, LOGIN_READ_TIMEOUT)
                .await
                .unwrap_or_default();
            if is_websocket_prefix(&prefix) {
                log::info!("wss control connection detected from {:?}", peer);
                let ws_conn = rust_frp_net::accept_websocket_stream(
                    rust_frp_net::PrefixedStream::new(prefix, tls_stream),
                    peer,
                )
                .await?;
                Box::new(ws_conn)
            } else {
                Box::new(rust_frp_net::PrefixedStream::new(prefix, tls_stream))
            }
        } else {
            // 处理普通 TCP 连接
            Box::new(conn)
        };

        // wire protocol v2 协商（非 v2 时原样回放嗅探字节，保持 v1 路径零变更）
        let control = Self::negotiate_control_conn(conn, &auth_manager).await?;

        Self::spawn_control(
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

        Ok(())
    }
}
