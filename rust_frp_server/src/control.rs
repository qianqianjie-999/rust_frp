//! 控制连接：登录会话、消息循环、客户端与 STCP 桥接管理

use rust_frp_auth::AuthManager;
use rust_frp_core::{
    ControlConn, Message, ProxyManager, ReqWorkConnMsg, StcpVisitorRespMsg, XtcpHolePunchMsg,
    XtcpNatInfoMsg,
};
use rust_frp_net::AnyConn;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, watch, RwLock};

use crate::*;

/// 控制器
pub struct Control {
    conn: ControlConn,
    run_id: String,
    user: String,
    client_id: String,
    proxy_manager: Arc<dyn ProxyManager + Send + Sync>,
    auth_manager: Arc<AuthManager>,
    /// 控制器管理器（用于注册客户端信息）
    control_manager: Arc<ControlManager>,
    last_heartbeat: Instant,
    registered_proxies: Vec<String>,
    /// 代理所有权映射 (proxy_name -> run_id)
    proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
    /// XTCP 访问者映射 (proxy_name -> visitor_run_id)
    xtcp_visitors: Arc<RwLock<std::collections::HashMap<String, String>>>,
    /// 登录成功通知通道
    login_tx: Option<mpsc::Sender<String>>,
    /// 消息发送通道（用于发送给客户端）
    pub(crate) msg_tx: Option<mpsc::Sender<Message>>,
    /// STCP 桥接管理器
    stcp_bridge_manager: Arc<StcpBridgeManager>,
    /// 工作连接管理器
    work_conn_manager: Arc<ServerWorkConnManager>,
    /// 工作连接池大小（来自客户端 LoginMsg）
    pool_count: u32,
    /// 工作连接是否启用 TLS（通过 LoginRespMsg 协商给客户端）
    work_conn_tls: bool,
    /// 客户端在 LoginMsg 中声明的扩展元数据（供插件回调透传）
    metas: std::collections::HashMap<String, String>,
    /// 服务端 HTTP 插件管理器（登录 / 注册 / 心跳 / 关闭代理回调）
    plugin_manager: Arc<rust_frp_plugin::server_plugin::Manager>,
    /// 上层已读取的登录消息（QUIC 流分派复用；仅首次 run 消费）
    pre_read_login: Option<rust_frp_core::LoginMsg>,
}

/// 构造控制会话所需的依赖集合（收敛 15 个独立参数，避免参数顺序误用）
pub struct ControlDeps {
    pub conn: ControlConn,
    pub run_id: String,
    pub user: String,
    pub client_id: String,
    pub proxy_manager: Arc<dyn ProxyManager + Send + Sync>,
    pub auth_manager: Arc<AuthManager>,
    pub control_manager: Arc<ControlManager>,
    pub proxy_owners: Arc<RwLock<std::collections::HashMap<String, String>>>,
    pub xtcp_visitors: Arc<RwLock<std::collections::HashMap<String, String>>>,
    pub login_tx: Option<mpsc::Sender<String>>,
    pub msg_tx: Option<mpsc::Sender<Message>>,
    pub stcp_bridge_manager: Arc<StcpBridgeManager>,
    pub work_conn_manager: Arc<ServerWorkConnManager>,
    pub work_conn_tls: bool,
    /// 上层已读取的登录消息（QUIC 流按首条消息分派时复用，避免重复读取）
    pub pre_read_login: Option<rust_frp_core::LoginMsg>,
    pub plugin_manager: Arc<rust_frp_plugin::server_plugin::Manager>,
}

impl Control {
    pub fn new(deps: ControlDeps) -> Self {
        let ControlDeps {
            conn,
            run_id,
            user,
            client_id,
            proxy_manager,
            auth_manager,
            control_manager,
            proxy_owners,
            xtcp_visitors,
            login_tx,
            msg_tx,
            stcp_bridge_manager,
            work_conn_manager,
            work_conn_tls,
            plugin_manager,
            pre_read_login,
        } = deps;
        Self {
            conn,
            run_id,
            user,
            client_id,
            proxy_manager,
            auth_manager,
            control_manager,
            last_heartbeat: Instant::now(),
            registered_proxies: Vec::new(),
            proxy_owners,
            xtcp_visitors,
            login_tx,
            msg_tx,
            stcp_bridge_manager,
            work_conn_manager,
            pool_count: 0, // 将在收到 LoginMsg 后由 run() 设置
            work_conn_tls,
            metas: std::collections::HashMap::new(),
            plugin_manager,
            pre_read_login,
        }
    }

    /// 构造插件回调的 UserInfo（user / run_id / metas）
    fn plugin_user_info(&self) -> serde_json::Value {
        serde_json::json!({
            "user": self.user,
            "run_id": self.run_id,
            "metas": self.metas,
        })
    }

    /// 发送消息到客户端（通过消息通道，供外部 visitor handler 调用）
    pub async fn send_msg(
        &self,
        msg: &Message,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(tx) = &self.msg_tx {
            tx.send(msg.clone()).await?;
            Ok(())
        } else {
            Err("Message channel not initialized".into())
        }
    }

    /// 清理该客户端注册的所有代理
    async fn cleanup_proxies(&self) {
        log::info!(
            "Client disconnected, cleaning up {} proxies",
            self.registered_proxies.len()
        );
        for proxy_name in &self.registered_proxies {
            log::info!("Removing proxy: {}", proxy_name);
            // 服务端插件回调：CloseProxy（单向通知，失败只记日志，不阻断清理）
            let close_content = serde_json::json!({
                "user": self.plugin_user_info(),
                "proxy_name": proxy_name,
            });
            self.plugin_manager.close_proxy(&close_content).await;
            // 关闭前落一份离线历史（含流量快照），供 /api/proxies?status=offline 查询
            if let Some(cfg) = self.proxy_manager.get_proxy_config(proxy_name).await {
                let (traffic_in, traffic_out, last_start_time) =
                    match global_metrics().get_proxy_stat(proxy_name) {
                        Some(stat) => {
                            let (i, o) = stat.totals();
                            (i, o, stat.created_at)
                        }
                        None => (0, 0, rust_frp_util::get_timestamp()),
                    };
                global_metrics().record_proxy_closed(crate::metrics::ClosedProxyInfo {
                    name: proxy_name.clone(),
                    proxy_type: cfg.r#type.clone(),
                    user: self.user.clone(),
                    client_id: self.client_id.clone(),
                    remote_port: cfg.remote_port,
                    last_start_time,
                    last_close_time: rust_frp_util::get_timestamp(),
                    traffic_in,
                    traffic_out,
                });
            }
            if let Err(e) = self.proxy_manager.remove_proxy(proxy_name).await {
                log::error!("Failed to remove proxy {}: {:?}", proxy_name, e);
            } else {
                log::info!("Removed proxy: {}", proxy_name);
            }
            global_metrics().remove_proxy_stat(proxy_name);
            // 清理代理所有权
            self.proxy_owners.write().await.remove(proxy_name);
            // 清理 STCP/XTCP 共享密钥登记
            global_proxy_secrets().remove(proxy_name);
        }
    }

    /// 写消息到客户端
    async fn write_msg(
        &mut self,
        msg: &Message,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 写方向超时（P1-2）：防止零窗口客户端无限阻塞控制任务
        tokio::time::timeout(WRITE_TIMEOUT, self.conn.write_message(msg))
            .await
            .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
                "write timeout: peer is not consuming data (zero-window?)".into()
            })?
    }

    pub async fn run(
        &mut self,
        mut msg_rx: mpsc::Receiver<Message>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log::info!("Control::run started");
        // 读取登录消息
        //
        // 安全：登录前读必须带超时（安全评审 P0-1）。否则未认证连接可以
        // 永久挂起本任务（Slowloris 式资源耗尽）；同时首帧上限收紧到
        // 64KB（P0-2），登录消息是几百字节量级的 JSON，无需 10MB 预算。
        // 读取登录消息；QUIC 流等由上层按首条消息分派时已读取，直接复用
        let msg_result = if let Some(login) = self.pre_read_login.take() {
            Ok(Message::Login(login))
        } else {
            match tokio::time::timeout(
                LOGIN_READ_TIMEOUT,
                self.conn
                    .read_message_with_limit(rust_frp_core::MAX_PREAUTH_MESSAGE_SIZE),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => {
                    log::warn!(
                        "Login read timed out after {:?}, closing unauthenticated connection",
                        LOGIN_READ_TIMEOUT
                    );
                    return Err("login read timeout".into());
                }
            }
        };

        match msg_result {
            Ok(msg) => {
                match msg {
                    Message::Login(login_msg) => {
                        log::info!("Received login message from user: {}", login_msg.user);
                        // 管理端 API 需要版本/主机名；下面的插件 json! 会移走这些字段，
                        // 因此先取出副本
                        let client_version = login_msg.version.clone();
                        let client_hostname = login_msg.hostname.clone();
                        // 验证登录
                        let verify_result = self
                            .auth_manager
                            .verify_login(&login_msg.user, &login_msg.token)
                            .await;
                        if let Err(e) = verify_result {
                            log::error!("Login verification failed: {:?}", e);
                            global_metrics().incr_login_failures();
                            return Err(format!("{:?}", e).into());
                        }
                        global_metrics().incr_login_successes();

                        // 服务端插件回调：Login（可拒绝登录，或用 unchange=false 覆写内容）。
                        // 安全：不向插件暴露客户端 token（仅传递业务字段）。
                        let mut plugin_content = serde_json::json!({
                            "user": login_msg.user,
                            "run_id": login_msg.run_id,
                            "client_id": login_msg.client_id,
                            "hostname": login_msg.hostname,
                            "os": login_msg.os,
                            "arch": login_msg.arch,
                            "version": login_msg.version,
                            "timestamp": login_msg.timestamp,
                            "pool_count": login_msg.pool_count,
                            "metas": login_msg.metas,
                        });
                        if let Err(reason) = self.plugin_manager.login(&mut plugin_content).await {
                            log::warn!(
                                "Login for user [{}] rejected by http plugin: {}",
                                plugin_content["user"].as_str().unwrap_or(""),
                                reason
                            );
                            global_metrics().incr_login_failures();
                            return Err(format!("login rejected by plugin: {}", reason).into());
                        }

                        // 更新控制器的信息（插件未覆写时与原值一致）
                        self.run_id = plugin_content["run_id"]
                            .as_str()
                            .unwrap_or_default()
                            .to_string();
                        self.user = plugin_content["user"]
                            .as_str()
                            .unwrap_or_default()
                            .to_string();
                        self.client_id = plugin_content["client_id"]
                            .as_str()
                            .unwrap_or_default()
                            .to_string();
                        self.pool_count = plugin_content["pool_count"].as_u64().unwrap_or(0) as u32;
                        self.metas = plugin_content["metas"]
                            .as_object()
                            .map(|o| {
                                o.iter()
                                    .filter_map(|(k, v)| {
                                        v.as_str().map(|s| (k.clone(), s.to_string()))
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();

                        // 注册客户端信息到 ControlManager（含版本/主机名/IP/线协议，供管理端 API）
                        let client_ip = self
                            .conn
                            .remote_addr()
                            .map(|a| a.ip().to_string())
                            .unwrap_or_default();
                        self.control_manager
                            .add_client(ClientRegistration {
                                run_id: self.run_id.clone(),
                                client_id: self.client_id.clone(),
                                user: self.user.clone(),
                                version: client_version,
                                hostname: client_hostname,
                                client_ip,
                                wire_protocol: self.conn.wire_protocol().as_str().to_string(),
                            })
                            .await;

                        // frpc 断线重连会用新 run_id、同 client_id 再次登录。
                        // 必须先踢掉旧连接并等它释放 proxy 端口，否则新连接注册同名
                        // proxy 会因端口占用失败，旧僵尸连接还会持续制造 502。
                        self.control_manager
                            .kick_same_client(&self.client_id, &self.run_id)
                            .await;

                        // 注册自己的"被踢"信号（下一次同客户端登录时，本次连接会被踢）
                        let (mut kick_rx, kick_done_tx) =
                            self.control_manager.register_kick(&self.run_id).await;
                        let mut kick_done_tx = Some(kick_done_tx);

                        // 发送登录响应（work_conn_tls 协商：服务器启用 TLS 时工作连接同步启用）
                        let resp = rust_frp_core::LoginRespMsg {
                            version: "0.1.0".to_string(),
                            run_id: self.run_id.clone(),
                            error: "".to_string(),
                            work_conn_tls: self.work_conn_tls,
                        };
                        let write_result = self.write_msg(&Message::LoginResp(resp)).await;
                        if let Err(e) = write_result {
                            log::error!("Failed to send login response: {:?}", e);
                            self.cleanup_proxies().await;
                            return Err(e);
                        }
                        log::info!("Sent login response to user: {}", self.user);

                        // 通知 handle_connection 登录成功
                        if let Some(tx) = self.login_tx.take() {
                            let _ = tx.send(self.run_id.clone()).await;
                        }

                        // 消息循环：使用 tokio::select! 同时处理读消息和发消息
                        // 参考 frp 的设计：同一个任务处理读写，无锁竞争
                        loop {
                            tokio::select! {
                                // 读取客户端消息（15秒读超时周期；半开判定见下方超时分支：
                                // 超过 90s 无任何心跳即判定 TCP 半开，强制清理 proxy）
                                msg_result = tokio::time::timeout(Duration::from_secs(15), self.conn.read_message()) => {
                                    match msg_result {
                                        Ok(Ok(msg)) => {
                                            match msg {
                                                Message::Ping(ping_msg) => {
                                                    self.handle_ping(ping_msg).await?;
                                                }
                                                Message::RegisterProxy(register_proxy_msg) => {
                                                    self.handle_register_proxy(register_proxy_msg).await?;
                                                }
                                                Message::ProxyStatus(proxy_status_msg) => {
                                                    self.handle_proxy_status(proxy_status_msg).await?;
                                                }
                                                Message::Disconnect(disconnect_msg) => {
                                                    log::info!("Received disconnect message from client: reason={}", disconnect_msg.reason);
                                                    self.cleanup_proxies().await;
                                                    log::info!("Control::run finished (graceful disconnect)");
                                                    return Ok(());
                                                }

                                                Message::UdpPacket(udp_msg) => {
                                                    self.handle_udp_packet(udp_msg).await;
                                                }
                                                Message::StcpVisitor(stcp_msg) => {
                                                    self.handle_stcp_visitor(stcp_msg).await?;
                                                }
                                                Message::XtcpNatInfo(xtcp_msg) => {
                                                    self.handle_xtcp_nat_info(xtcp_msg).await?;
                                                }
                                                Message::XtcpHolePunch(hp_msg) => {
                                                    self.handle_xtcp_hole_punch(hp_msg).await;
                                                }
                                                _ => {
                                                    log::warn!("unexpected message in loop: {:?}", msg);
                                                }

                                            }
                                        }
                                        Ok(Err(e)) => {
                                            log::warn!("Client connection closed unexpectedly: {:?}", e);
                                            self.cleanup_proxies().await;
                                            return Ok(());
                                        }
                                        Err(_elapsed) => {
                                            // 15s 周期内没读到任何消息；若距上次心跳已超过 90s，
                                            // 判定 TCP 半开（对端已死但无 RST），强制清理 proxy，
                                            // 否则旧端口不释放、frpc 重连注册失败 → 长时间 502
                                            if self.last_heartbeat.elapsed() > Duration::from_secs(90) {
                                                log::warn!(
                                                    "Heartbeat timeout for client {} (no ping for {:?}), force closing half-open connection",
                                                    self.client_id,
                                                    self.last_heartbeat.elapsed()
                                                );
                                                self.cleanup_proxies().await;
                                                return Err("client heartbeat timeout".into());
                                            }
                                        }
                                    }
                                },
                                // 被同一客户端的新登录踢下线（frpc 断线重连场景）
                                _ = kick_rx.changed() => {
                                    log::warn!("Kicked by new session for client: {}", self.client_id);
                                    self.cleanup_proxies().await;
                                    if let Some(tx) = kick_done_tx.take() {
                                        let _ = tx.send(());
                                    }
                                    return Ok(());
                                },
                                // 接收要发送的消息（来自 visitor handler）
                                msg = msg_rx.recv() => {
                                    match msg {
                                        Some(msg_to_send) => {
                                            if let Err(e) = self.write_msg(&msg_to_send).await {
                                                log::error!("Failed to send message via channel: {:?}", e);
                                            }
                                        }
                                        None => {
                                            log::warn!("Message sender dropped, exiting loop");
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        log::warn!("unexpected first message: {:?}", msg);
                        return Err("Unexpected first message".into());
                    }
                }
            }
            Err(e) => {
                log::error!("read login message error: {:?}", e);
                self.cleanup_proxies().await;
                log::info!("Control::run finished");
                return Err(e);
            }
        }

        Ok(())
    }
    /// 心跳：刷新 last_heartbeat 并回 Pong
    async fn handle_ping(
        &mut self,
        ping_msg: rust_frp_core::PingMsg,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.last_heartbeat = Instant::now();

        // additionalScopes 含 heartBeats 时强校验心跳签名（fail-closed：
        // 缺失/错误签名 → 断开控制连接，对齐原版 VerifyPing 语义）
        self.auth_manager
            .verify_ping_privilege_key(ping_msg.timestamp, &ping_msg.privilege_key)?;

        // 服务端插件回调：Ping（reject 时回带 error 的 Pong，客户端据此重连）
        let mut plugin_content = serde_json::json!({
            "user": self.plugin_user_info(),
            "timestamp": ping_msg.timestamp,
        });
        let plugin_error = self.plugin_manager.ping(&mut plugin_content).await.err();

        let pong_msg = rust_frp_core::PongMsg {
            timestamp: ping_msg.timestamp,
            error: plugin_error.unwrap_or_default(),
        };
        if let Err(e) = self.write_msg(&Message::Pong(pong_msg)).await {
            log::error!("Failed to send pong message: {:?}", e);
            self.cleanup_proxies().await;
            return Err(e);
        }
        Ok(())
    }

    /// 代理注册：登记 proxy_owners/secret_key/metrics 并回执
    async fn handle_register_proxy(
        &mut self,
        register_proxy_msg: rust_frp_core::RegisterProxyMsg,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut proxy = register_proxy_msg.proxy;
        let proxy_name = proxy.name.clone();
        let proxy_type = proxy.r#type.clone();
        let proxy_remote_port = proxy.remote_port;
        let proxy_secret_key = proxy.secret_key.clone();

        // 服务端插件回调：NewProxy（可拒绝注册，或用 unchange=false 覆写代理配置）。
        // content 与原版对齐：user 字段 + 代理配置平铺。
        let mut plugin_content = {
            let mut map = serde_json::Map::new();
            map.insert("user".to_string(), self.plugin_user_info());
            if let Ok(serde_json::Value::Object(cfg)) = serde_json::to_value(&proxy) {
                for (k, v) in cfg {
                    map.insert(k, v);
                }
            }
            serde_json::Value::Object(map)
        };
        if let Err(reason) = self.plugin_manager.new_proxy(&mut plugin_content).await {
            log::warn!(
                "New proxy [{}] rejected by http plugin: {}",
                proxy_name,
                reason
            );
            let resp = rust_frp_core::RegisterProxyRespMsg {
                name: proxy_name.clone(),
                error: format!("new proxy rejected by plugin: {}", reason),
            };
            if let Err(e) = self.write_msg(&Message::RegisterProxyResp(resp)).await {
                log::error!("Failed to send register proxy rejection: {:?}", e);
                self.cleanup_proxies().await;
                return Err(e);
            }
            return Ok(());
        }
        // 插件覆写：仅在能完整反序列化为 ProxyConfig 时采用（默认内容即原配置，二者等价）
        if let Some(obj) = plugin_content.as_object() {
            let mut cfg_obj = obj.clone();
            cfg_obj.remove("user");
            if let Ok(new_cfg) = serde_json::from_value::<rust_frp_config::ProxyConfig>(
                serde_json::Value::Object(cfg_obj),
            ) {
                proxy = new_cfg;
            }
        }

        let result = self
            .proxy_manager
            .add_proxy_for_user(proxy, &self.user)
            .await;

        let error_msg = match result {
            Ok(_) => {
                self.registered_proxies.push(proxy_name.clone());
                self.proxy_owners
                    .write()
                    .await
                    .insert(proxy_name.clone(), self.run_id.clone());
                // stcp/xtcp 代理登记共享密钥，供访问者签名校验（fail-closed）
                if matches!(proxy_type.as_str(), "stcp" | "xtcp") {
                    match proxy_secret_key.as_deref() {
                        Some(sk) if !sk.is_empty() => {
                            global_proxy_secrets().register(&proxy_name, sk);
                            log::info!(
                                "secret_key registered for {} proxy: {}",
                                proxy_type,
                                proxy_name
                            );
                        }
                        _ => {
                            log::warn!(
                                "stcp/xtcp/sudp proxy {} has no secret_key configured; visitor access will be rejected",
                                proxy_name
                            );
                        }
                    }
                }
                global_metrics().register_proxy_stat(&proxy_name, &proxy_type, proxy_remote_port);
                "".to_string()
            }
            Err(e) => format!("{:?}", e),
        };

        let resp = rust_frp_core::RegisterProxyRespMsg {
            name: proxy_name.clone(),
            error: error_msg.clone(),
        };

        if let Err(e) = self.write_msg(&Message::RegisterProxyResp(resp)).await {
            log::error!("Failed to send register proxy response: {:?}", e);
            self.cleanup_proxies().await;
            return Err(e);
        }

        if error_msg.is_empty() {
            log::info!("proxy registered: {}", proxy_name);
            // 初始化工作连接池（不做预填充，由 get_work_conn 的取后补充自然填充）
            self.work_conn_manager.init_pool(&proxy_name).await;
        } else {
            log::error!("failed to register proxy {}: {}", proxy_name, error_msg);
        }
        Ok(())
    }

    /// 查询代理状态并回执
    async fn handle_proxy_status(
        &mut self,
        proxy_status_msg: rust_frp_core::ProxyStatusMsg,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let status = self
            .proxy_manager
            .get_proxy_status(&proxy_status_msg.name)
            .await
            .map_err(|e| format!("{:?}", e))?;
        let resp = rust_frp_core::ProxyStatusRespMsg {
            name: proxy_status_msg.name,
            status: status.unwrap_or_else(|| "unknown".to_string()),
            error: "".to_string(),
        };
        if let Err(e) = self.write_msg(&Message::ProxyStatusResp(resp)).await {
            log::error!("Failed to send proxy status response: {:?}", e);
            self.cleanup_proxies().await;
            return Err(e);
        }
        Ok(())
    }

    /// 转发 UDP 包给对应访问者
    async fn handle_udp_packet(&mut self, udp_msg: rust_frp_core::UdpPacketMsg) {
        if let Some(addr) = &udp_msg.client_addr {
            if let Err(e) = self
                .proxy_manager
                .send_udp_packet(&udp_msg.proxy_name, &udp_msg.data, addr)
                .await
            {
                log::error!("Failed to send UDP packet to visitor: {:?}", e);
            }
        }
    }

    /// STCP 访客请求：fail-closed 签名校验 + 建桥（跨客户端支持）
    async fn handle_stcp_visitor(
        &mut self,
        stcp_msg: rust_frp_core::StcpVisitorMsg,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log::info!(
            "Received STCP visitor request for proxy {} from client {}",
            stcp_msg.proxy_name,
            self.run_id
        );

        let proxy_name = stcp_msg.proxy_name.clone();
        let visitor_run_id = self.run_id.clone();

        // 查代理所有者与注册的共享密钥（先取值再 await，避免跨 await 持锁）
        let (proxy_run_id, registered_secret) = {
            let owners = self.proxy_owners.read().await;
            let owner = owners.get(&proxy_name).cloned();
            let secret = global_proxy_secrets().get(&proxy_name);
            (owner, secret)
        };

        // fail-closed：代理不存在、未登记 secret_key、签名不匹配均拒绝
        let rejection = match (&proxy_run_id, &registered_secret) {
            (None, _) => Some("proxy not found".to_string()),
            (Some(_), None) => {
                log::error!(
                    "STCP proxy {} has no secret_key registered; rejecting visitor {}",
                    proxy_name,
                    visitor_run_id
                );
                Some("proxy secret_key not configured".to_string())
            }
            (Some(_), Some(secret)) => {
                if verify_stcp_visitor_sign(
                    secret,
                    &proxy_name,
                    stcp_msg.timestamp,
                    &stcp_msg.sign_key,
                ) {
                    None
                } else {
                    log::error!(
                        "STCP visitor sign verification failed for proxy {} (visitor {})",
                        proxy_name,
                        visitor_run_id
                    );
                    Some("invalid secret key".to_string())
                }
            }
        };

        if let Some(error) = rejection {
            let resp = StcpVisitorRespMsg {
                proxy_name: proxy_name.clone(),
                error,
                visitor_run_id,
            };
            if let Err(e) = self.write_msg(&Message::StcpVisitorResp(resp)).await {
                log::error!("Failed to send StcpVisitorResp: {:?}", e);
            }
            return Ok(());
        }

        // 签名校验通过：允许同客户端与跨客户端访问，
        // 桥接以 proxy_name 为 id，双方各自建工作连接后由桥接管理器配对
        let Some(proxy_run_id) = &proxy_run_id else {
            log::error!(
                "STCP proxy {} lost its owner during sign verification; aborting bridge",
                proxy_name
            );
            return Ok(());
        };
        self.stcp_bridge_manager
            .create_bridge(proxy_name.clone())
            .await;

        let msg_tx_proxy = self.control_manager.get_msg_tx(proxy_run_id).await;
        let msg_tx_visitor = self.control_manager.get_msg_tx(&visitor_run_id).await;

        if let Some(tx) = &msg_tx_proxy {
            let req = ReqWorkConnMsg {
                proxy_name: proxy_name.clone(),
            };
            if let Err(e) = tx.send(Message::ReqWorkConn(req)).await {
                log::error!("Failed to send ReqWorkConn to proxy: {:?}", e);
            }
        }

        if let Some(tx) = &msg_tx_visitor {
            let req = ReqWorkConnMsg {
                proxy_name: proxy_name.clone(),
            };
            if let Err(e) = tx.send(Message::ReqWorkConn(req)).await {
                log::error!("Failed to send ReqWorkConn to visitor: {:?}", e);
            }
        }

        let resp = StcpVisitorRespMsg {
            proxy_name: proxy_name.clone(),
            error: String::new(),
            visitor_run_id: visitor_run_id.clone(),
        };
        if let Err(e) = self.write_msg(&Message::StcpVisitorResp(resp)).await {
            log::error!("Failed to send StcpVisitorResp: {:?}", e);
        }
        Ok(())
    }

    /// XTCP NAT 信息：visitor 侧签名校验后中继给 owner，owner 侧回传 visitor
    async fn handle_xtcp_nat_info(
        &mut self,
        xtcp_msg: rust_frp_core::XtcpNatInfoMsg,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log::info!(
            "Received XTCP NAT info for proxy {} from {}",
            xtcp_msg.proxy_name,
            self.run_id
        );

        let proxy_name = xtcp_msg.proxy_name.clone();
        let from_run_id = self.run_id.clone();

        let owner_run_id = {
            let owners = self.proxy_owners.read().await;
            owners.get(&proxy_name).cloned()
        };

        let owner_run_id = match owner_run_id {
            Some(id) => id,
            None => {
                log::error!("No proxy owner found for XTCP: {}", proxy_name);
                return Ok(());
            }
        };

        let mut relay = XtcpNatInfoMsg {
            proxy_name: proxy_name.clone(),
            run_id: from_run_id.clone(),
            nat_type: xtcp_msg.nat_type.clone(),
            local_addr: xtcp_msg.local_addr.clone(),
            public_addr: xtcp_msg.public_addr.clone(),
            sign_key: xtcp_msg.sign_key.clone(),
            timestamp: xtcp_msg.timestamp,
        };

        if from_run_id != owner_run_id {
            // 来自 visitor：先校验 secret_key 签名（fail-closed）
            let registered_secret = global_proxy_secrets().get(&proxy_name);
            let sign_ok = match &registered_secret {
                Some(secret) => verify_stcp_visitor_sign(
                    secret,
                    &proxy_name,
                    xtcp_msg.timestamp,
                    &xtcp_msg.sign_key,
                ),
                None => false,
            };
            if !sign_ok {
                log::error!(
                    "XTCP visitor sign verification failed for proxy {} (visitor {})",
                    proxy_name,
                    from_run_id
                );
                return Ok(());
            }
            // 校验通过后转发时不携带签名（owner 侧无需也不可信）
            relay.sign_key = String::new();

            // 存储 visitor run_id 并中继给 proxy owner
            {
                let mut visitors = self.xtcp_visitors.write().await;
                visitors.insert(proxy_name.clone(), from_run_id.clone());
            }
            log::info!("XTCP visitor registered: {} -> {}", proxy_name, from_run_id);

            let target_tx = self.control_manager.get_msg_tx(&owner_run_id).await;
            if let Some(tx) = &target_tx {
                if let Err(e) = tx.send(Message::XtcpNatInfo(relay)).await {
                    log::error!("Failed to relay XTCP NAT info to owner: {:?}", e);
                }
            }
        } else {
            // 来自 proxy owner，中继给 visitor
            let visitor_run_id = {
                let visitors = self.xtcp_visitors.read().await;
                visitors.get(&proxy_name).cloned()
            };

            match visitor_run_id {
                Some(vid) => {
                    let target_tx = self.control_manager.get_msg_tx(&vid).await;
                    if let Some(tx) = &target_tx {
                        if let Err(e) = tx.send(Message::XtcpNatInfo(relay)).await {
                            log::error!("Failed to relay XTCP NAT info to visitor: {:?}", e);
                        } else {
                            log::info!(
                                "Relayed XTCP NAT info from owner {} to visitor {}",
                                from_run_id,
                                vid
                            );
                        }
                    }
                }
                None => {
                    log::info!(
                        "No XTCP visitor yet for proxy {}, NAT info from owner stored",
                        proxy_name
                    );
                }
            }
        }
        Ok(())
    }

    /// XTCP 打洞消息中继
    async fn handle_xtcp_hole_punch(&mut self, hp_msg: rust_frp_core::XtcpHolePunchMsg) {
        let to_run_id = hp_msg.to_run_id.clone();
        let relay = XtcpHolePunchMsg {
            proxy_name: hp_msg.proxy_name.clone(),
            from_run_id: hp_msg.from_run_id.clone(),
            to_run_id: to_run_id.clone(),
            peer_local_addr: hp_msg.peer_local_addr.clone(),
            peer_public_addr: hp_msg.peer_public_addr.clone(),
        };

        let target_tx = self.control_manager.get_msg_tx(&to_run_id).await;
        if let Some(tx) = &target_tx {
            if let Err(e) = tx.send(Message::XtcpHolePunch(relay)).await {
                log::error!("Failed to relay XTCP hole punch: {:?}", e);
            }
        }
    }
}

/// 离线客户端历史最大保留条数（FIFO 淘汰）
pub const MAX_OFFLINE_CLIENTS: usize = 200;

/// 客户端连接信息（在线条目 + 历史离线条目共用同一结构）
#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub run_id: String,
    pub client_id: String,
    pub user: String,
    /// 客户端版本（登录消息携带）
    pub version: String,
    /// 客户端主机名（登录消息携带）
    pub hostname: String,
    /// 客户端来源 IP（可为空，如多路复用/QUIC 路径拿不到对端地址时）
    pub client_ip: String,
    /// 线协议版本标识（v1 / v2）
    pub wire_protocol: String,
    pub connected_at: Instant,
    pub last_heartbeat: Instant,
    /// 最近一次上线时间（Unix 秒）
    pub first_connected_at: i64,
    /// 最近一次离线时间（Unix 秒；在线时为 None）
    pub disconnected_at: Option<i64>,
    /// 是否在线
    pub online: bool,
}

impl ClientInfo {
    /// 客户端唯一键：`base64(user|client_id|run_id)`（URL 安全、无填充）
    ///
    /// 与 `/api/clients/{key}` 的 key 语义对应；用 URL 安全字母表是为了让
    /// key 可以直接放进路径而无需额外转义。
    pub fn key(&self) -> String {
        base64::encode_config(
            format!("{}|{}|{}", self.user, self.client_id, self.run_id),
            base64::URL_SAFE_NO_PAD,
        )
    }
}

/// 登录成功时的客户端注册信息（供 [`ControlManager::add_client`] 使用）
pub struct ClientRegistration {
    pub run_id: String,
    pub client_id: String,
    pub user: String,
    pub version: String,
    pub hostname: String,
    pub client_ip: String,
    pub wire_protocol: String,
}

/// 踢连接信号表：run_id -> (kick 通知, 清理完成回执接收端)
type KickSignalMap =
    RwLock<std::collections::HashMap<String, (watch::Sender<()>, oneshot::Receiver<()>)>>;

/// 控制器管理器：维护在线客户端、消息通道与被踢信号
pub struct ControlManager {
    // 存储 run_id -> msg_tx 映射，用于向客户端发送消息
    msg_channels: RwLock<std::collections::HashMap<String, mpsc::Sender<Message>>>,
    // 存储客户端连接信息 (run_id -> ClientInfo)
    clients: RwLock<std::collections::HashMap<String, ClientInfo>>,
    // 已断开客户端的历史信息（FIFO，供管理端 offline 查询）
    offline_clients: RwLock<Vec<ClientInfo>>,
    // 踢连接信号：同一 client_id 重复登录时，用它通知旧 Control 退出并等待其释放 proxy
    kick_signals: KickSignalMap,
}

impl Default for ControlManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlManager {
    pub fn new() -> Self {
        Self {
            msg_channels: RwLock::new(std::collections::HashMap::new()),
            clients: RwLock::new(std::collections::HashMap::new()),
            kick_signals: RwLock::new(std::collections::HashMap::new()),
            offline_clients: RwLock::new(Vec::new()),
        }
    }

    pub async fn add(
        &self,
        run_id: String,
        msg_tx: mpsc::Sender<Message>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut msg_channels = self.msg_channels.write().await;
        msg_channels.insert(run_id.clone(), msg_tx);
        Ok(())
    }

    pub async fn remove(
        &self,
        run_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut msg_channels = self.msg_channels.write().await;
        msg_channels.remove(run_id);

        // 在线条目转存离线历史（保留 version/hostname/client_ip 供管理端查询）
        {
            let mut clients = self.clients.write().await;
            if let Some(mut info) = clients.remove(run_id) {
                info.online = false;
                info.disconnected_at = Some(rust_frp_util::get_timestamp());
                let mut offline = self.offline_clients.write().await;
                offline.retain(|c| c.run_id != info.run_id);
                offline.push(info);
                if offline.len() > MAX_OFFLINE_CLIENTS {
                    let overflow = offline.len() - MAX_OFFLINE_CLIENTS;
                    offline.drain(..overflow);
                }
            }
        }

        // 顺带清理踢连接信号
        self.kick_signals.write().await.remove(run_id);
        Ok(())
    }

    /// Control 连接进入消息循环前注册自己的"被踢"信号。
    /// 返回 (kick 接收端, 清理完成回执发送端)：
    /// 收到 kick 信号 → cleanup_proxies → 通过 done 回执通知等待方
    pub async fn register_kick(&self, run_id: &str) -> (watch::Receiver<()>, oneshot::Sender<()>) {
        let (kick_tx, kick_rx) = watch::channel(());
        let (done_tx, done_rx) = oneshot::channel();
        self.kick_signals
            .write()
            .await
            .insert(run_id.to_string(), (kick_tx, done_rx));
        (kick_rx, done_tx)
    }

    /// 同一 client_id 的客户端重复登录时（frpc 断线重连），踢掉旧连接，
    /// 并同步等待旧 Control 清理完 proxy（释放服务端端口），避免新连接
    /// 注册同名 proxy 时因端口占用而失败导致长时间 502。
    pub async fn kick_same_client(&self, client_id: &str, new_run_id: &str) {
        // 先找出同 client_id 的旧 run_id（只读锁内不 await 其他锁，防死锁）
        let old_run_ids: Vec<String> = {
            let clients = self.clients.read().await;
            clients
                .values()
                .filter(|c| c.client_id == client_id && c.run_id != new_run_id)
                .map(|c| c.run_id.clone())
                .collect()
        };

        for old_run_id in old_run_ids {
            log::warn!(
                "client '{}' re-logged in with new run_id {}, kicking old session {}",
                client_id,
                new_run_id,
                old_run_id
            );

            // 取出旧连接的 kick 信号并触发
            let signal = self.kick_signals.write().await.remove(&old_run_id);
            if let Some((kick_tx, done_tx)) = signal {
                let _ = kick_tx.send(());
                // 等待旧 Control 完成 proxy 清理（stop_proxy 内含 ~100ms 等待），
                // 最多等 5 秒兜底，防止异常情况下新连接登录被无限阻塞
                let wait_result = tokio::time::timeout(Duration::from_secs(5), done_tx).await;
                if wait_result.is_err() {
                    log::warn!(
                        "old session {} did not finish cleanup within 5s",
                        old_run_id
                    );
                }
            }

            // 兜底：直接清掉旧连接的注册表项（正常情况下旧 Control 退出时也会自清理）
            self.msg_channels.write().await.remove(&old_run_id);
            self.clients.write().await.remove(&old_run_id);
        }
    }

    pub async fn get_msg_tx(&self, run_id: &str) -> Option<mpsc::Sender<Message>> {
        let msg_channels = self.msg_channels.read().await;
        msg_channels.get(run_id).cloned()
    }

    /// 添加或更新客户端信息
    pub async fn add_client(&self, reg: ClientRegistration) {
        let now = Instant::now();
        let info = ClientInfo {
            run_id: reg.run_id.clone(),
            client_id: reg.client_id,
            user: reg.user,
            version: reg.version,
            hostname: reg.hostname,
            client_ip: reg.client_ip,
            wire_protocol: reg.wire_protocol,
            connected_at: now,
            last_heartbeat: now,
            first_connected_at: rust_frp_util::get_timestamp(),
            disconnected_at: None,
            online: true,
        };
        let mut clients = self.clients.write().await;
        // 同一 run_id 重新上线：从离线历史中移除，避免两个列表重复
        let mut offline = self.offline_clients.write().await;
        offline.retain(|c| c.run_id != info.run_id);
        clients.insert(reg.run_id, info);
    }

    /// 更新客户端心跳时间
    pub async fn update_heartbeat(&self, run_id: &str) {
        let mut clients = self.clients.write().await;
        if let Some(client) = clients.get_mut(run_id) {
            client.last_heartbeat = Instant::now();
        }
    }

    /// 获取所有**在线**客户端列表
    pub async fn get_clients(&self) -> Vec<ClientInfo> {
        let clients = self.clients.read().await;
        clients.values().cloned().collect()
    }

    /// 获取在线 + 历史离线的全部客户端（供管理端 `/api/clients` 使用）
    pub async fn get_all_clients(&self) -> Vec<ClientInfo> {
        let mut all: Vec<ClientInfo> = self.clients.read().await.values().cloned().collect();
        all.extend(self.offline_clients.read().await.iter().cloned());
        all
    }

    /// 清理离线客户端历史，返回被清理条数
    pub async fn clear_offline_clients(&self) -> usize {
        let mut offline = self.offline_clients.write().await;
        let cleared = offline.len();
        offline.clear();
        cleared
    }

    /// 按 key 查询客户端（在线优先，其次离线历史）
    pub async fn get_client_by_key(&self, key: &str) -> Option<ClientInfo> {
        {
            let clients = self.clients.read().await;
            if let Some(c) = clients.values().find(|c| c.key() == key) {
                return Some(c.clone());
            }
        }
        self.offline_clients
            .read()
            .await
            .iter()
            .find(|c| c.key() == key)
            .cloned()
    }

    /// 按 run_id 查询用户名（供插件回调构造 UserInfo）
    pub async fn get_user_by_run_id(&self, run_id: &str) -> Option<String> {
        self.clients
            .read()
            .await
            .get(run_id)
            .map(|c| c.user.clone())
    }
}

/// STCP 桥接状态，用于等待两个客户端的工连接并桥接
pub(crate) struct StcpBridgeState {
    conn1: Option<AnyConn>,
    conn2: Option<AnyConn>,
}

/// STCP 桥接管理器，用于协调两个客户端的工作连接
pub struct StcpBridgeManager {
    bridges: RwLock<std::collections::HashMap<String, StcpBridgeState>>,
}

impl Default for StcpBridgeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl StcpBridgeManager {
    pub fn new() -> Self {
        Self {
            bridges: RwLock::new(std::collections::HashMap::new()),
        }
    }

    pub async fn create_bridge(&self, bridge_id: String) {
        let mut bridges = self.bridges.write().await;
        bridges.insert(
            bridge_id,
            StcpBridgeState {
                conn1: None,
                conn2: None,
            },
        );
    }

    /// 添加连接并尝试桥接。
    /// 返回 Some((c1, c2)) 表示桥接已就绪
    /// 返回 None 表示连接已存储（等待另一半）
    /// 返回 Err 表示没有此桥接（连接未消耗）
    pub async fn add_conn_and_try_bridge(
        &self,
        bridge_id: &str,
        conn: AnyConn,
    ) -> Result<Option<(AnyConn, AnyConn)>, AnyConn> {
        let mut bridges = self.bridges.write().await;
        if let Some(state) = bridges.get_mut(bridge_id) {
            if state.conn1.is_none() {
                state.conn1 = Some(conn);
                Ok(None)
            } else if state.conn2.is_none() {
                state.conn2 = Some(conn);
                // 不变量：bridge 存在于 map 且 conn1/conn2 均已就位（上方分支保证）
                let mut state = bridges
                    .remove(bridge_id)
                    .expect("bridge state must exist (checked above)");
                let c1 = state
                    .conn1
                    .take()
                    .expect("conn1 must be set before bridging");
                let c2 = state
                    .conn2
                    .take()
                    .expect("conn2 must be set before bridging");
                Ok(Some((c1, c2)))
            } else {
                Ok(None)
            }
        } else {
            Err(conn)
        }
    }

    pub async fn cleanup(&self, bridge_id: &str) {
        let mut bridges = self.bridges.write().await;
        bridges.remove(bridge_id);
    }
}
