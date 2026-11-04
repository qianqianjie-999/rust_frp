//! Server 的 control 相关实现（原 server.rs 的 `impl Server` 片段）。

use super::*;

impl Server {
    /// 控制连接线协议协商（wire protocol v2）
    ///
    /// 嗅探对方前 [`MAGIC_V2`](rust_frp_net::wire_v2::MAGIC_V2) 长度的字节：
    /// - 命中魔数 → 完成 ClientHello/ServerHello 能力协商，返回以方向性 AEAD
    ///   （HKDF 从 `SHA-256(token)` 派生）包装的连接 + [`WireProtocol::V2`]；
    /// - 未命中 → 通过 [`rust_frp_net::PrefixedStream`] 把嗅探字节原样回放，
    ///   返回 [`WireProtocol::V1`]，v1 解析路径零变更。
    ///
    /// 嗅探带超时，避免未认证连接长期占用任务（延续 P0-1 约束）。
    pub(super) async fn negotiate_control_conn(
        conn: AnyConn,
        auth_manager: &AuthManager,
    ) -> Result<ControlConn, Box<dyn std::error::Error + Send + Sync>> {
        let mut conn = conn;
        let sniffed = tokio::time::timeout(
            LOGIN_READ_TIMEOUT,
            rust_frp_net::wire_v2::check_magic(&mut conn),
        )
        .await
        .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
            "wire protocol sniff timed out".into()
        })?
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("wire protocol sniff failed: {e}").into()
        })?;
        let (prefix, is_v2) = sniffed;

        if !is_v2 {
            return Ok(ControlConn::new(Box::new(
                rust_frp_net::PrefixedStream::new(prefix, conn),
            )));
        }

        let base_key = auth_manager.encryption_key().ok_or(
            "wire protocol v2 requires a token on the server: \
             the v2 control channel derives its AEAD keys from SHA-256(token)",
        )?;
        let encrypted = rust_frp_net::wire_v2::server_handshake(conn, base_key)
            .await
            .map_err(|e| format!("wire v2 handshake failed: {e}"))?;
        log::info!("wire protocol v2 negotiated with client");
        Ok(ControlConn::new_v2(Box::new(encrypted)))
    }

    /// 启动控制连接处理任务（登录注册 + 控制循环 + 退出清理）
    ///
    /// 返回任务句柄：多路复用路径在控制流退出后据此关闭会话。
    ///
    /// `plaintext_ws`：该控制连接是否来自**明文 WebSocket** 分支（无 TLS）。
    /// 仅用于登录成功后的 WARN 提示（P1 可观测性）—— 原先这条路径完全静默，
    /// 无法区分"扫描器踩到"与"合法客户端真在用"。
    pub(super) fn spawn_control(
        conn: ControlConn,
        managers: ServerManagers,
        auth_manager: Arc<AuthManager>,
        work_conn_tls: bool,
        pre_read_login: Option<rust_frp_core::LoginMsg>,
        peer_cert_fingerprint: Option<String>,
        plaintext_ws: bool,
    ) -> tokio::task::JoinHandle<()> {
        let ServerManagers {
            control_manager,
            proxy_manager,
            proxy_owners,
            xtcp_visitors,
            stcp_bridge_manager,
            work_conn_manager,
            plugin_manager,
            work_conn_port,
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
            work_conn_port,
            pre_read_login,
            plugin_manager,
            peer_cert_fingerprint,
        });

        // 克隆 msg_tx 用于注册
        let msg_tx_clone = control.msg_tx.clone();

        tokio::spawn(async move {
            // 优雅关闭排空：控制会话存活期间保持全局连接计数（accept 包装
            // 任务在握手移交后即返回减计数，长寿命会话由此守卫覆盖）
            let _drain_guard = global_metrics().connection_guard();
            // 启动控制循环
            let run_handle = tokio::spawn(async move {
                if let Err(e) = control.run(msg_rx).await {
                    log::error!("control run error: {:?}", e);
                }
            });

            // 等待登录成功，然后注册 msg_tx 到 ControlManager
            if let Some(run_id) = login_rx.recv().await {
                log::info!("Control registered for run_id: {}", run_id);
                if plaintext_ws {
                    log::warn!(
                        "Control connection for run_id {} authenticated over a PLAINTEXT \
                         websocket (no TLS ⇒ no client certificate check). Close this path with \
                         transport.tls.enable = true + require_client_cert = true (or tls_only = true).",
                        run_id
                    );
                }
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
}
