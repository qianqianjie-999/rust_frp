//! 从 lib.rs 拆出的 sudp 实现。

use super::*;

/// 访问者隧道心跳间隔（代理侧发送，用于让访问者感知隧道存活）
pub(super) const SUDP_HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
/// 访问者隧道空闲上限（连续两个心跳周期无消息即判定会话结束）
pub(super) const SUDP_TUNNEL_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// sudp 访问者会话表（会话任务自行摘除，避免陈旧会话常驻）
pub(super) type SudpSessions =
    Arc<Mutex<std::collections::HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>;

/// 隧道写任务：从通道取消息写入已建立的工作连接
///
/// 返回发送端；写入失败时任务自行结束（后续发送返回错误，调用方据此回收会话）。
pub(super) fn spawn_tunnel_writer<W>(mut writer: W) -> mpsc::Sender<Message>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::channel::<Message>(1024);
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = rust_frp_core::write_message(&mut writer, &msg).await {
                log::debug!("sudp: tunnel writer closed: {:?}", e);
                break;
            }
        }
    });
    tx
}

/// 代理侧心跳：周期性投递 Ping，供访问者侧判定隧道是否存活
///
/// 返回任务句柄，隧道读循环结束后由调用方 `abort`，避免半关闭场景下
/// 心跳任务持有的发送端让写任务无法退出。
pub(super) fn spawn_sudp_heartbeat(out_tx: mpsc::Sender<Message>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SUDP_HEARTBEAT_INTERVAL);
        ticker.tick().await; // 跳过 interval 的立即首次 tick
        loop {
            ticker.tick().await;
            // sudp 隧道内 keepalive（frpc↔frpc），非控制面心跳，不做 additionalScopes 签名
            let ping = Message::Ping(rust_frp_core::PingMsg {
                timestamp: get_timestamp(),
                privilege_key: String::new(),
            });
            if out_tx.send(ping).await.is_err() {
                break;
            }
        }
    })
}

/// sudp 代理侧：把工作连接上的 UDP 包帧转发到本地 UDP 服务
///
/// 每个访问者源地址对应一个独立本地 UDP 会话（连接到 `local_addr` 的临时
/// socket），保证本地服务回包能准确回到对应访问者。
pub(super) async fn serve_sudp_proxy(
    work_conn: Box<dyn rust_frp_net::FrpConn>,
    proxy_name: &str,
    local_addr: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    log::info!(
        "sudp proxy {} tunnel established, forwarding to local udp {}",
        proxy_name,
        local_addr
    );

    let (mut reader, writer) = tokio::io::split(work_conn);
    let out_tx = spawn_tunnel_writer(writer);
    let heartbeat = spawn_sudp_heartbeat(out_tx.clone());

    let mut sessions: std::collections::HashMap<String, mpsc::Sender<Vec<u8>>> =
        std::collections::HashMap::new();

    loop {
        let msg = match rust_frp_core::read_message(&mut reader).await {
            Ok(msg) => msg,
            Err(e) => {
                log::debug!("sudp proxy {} tunnel closed: {:?}", proxy_name, e);
                break;
            }
        };
        let Message::UdpPacket(packet) = msg else {
            continue;
        };
        let Some(client_addr) = packet.client_addr else {
            continue;
        };

        let inbound = match sessions.get(&client_addr) {
            Some(tx) => tx.clone(),
            None => {
                let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
                spawn_sudp_local_session(
                    client_addr.clone(),
                    local_addr.clone(),
                    proxy_name.to_string(),
                    rx,
                    out_tx.clone(),
                );
                sessions.insert(client_addr.clone(), tx.clone());
                tx
            }
        };
        if inbound.send(packet.data).await.is_err() {
            sessions.remove(&client_addr);
        }
    }

    log::info!("sudp proxy {} tunnel ended", proxy_name);
    heartbeat.abort();
    Ok(())
}

/// 单个访问者对应的本地 UDP 会话：入站载荷 → 本地服务，回包 → 隧道
pub(super) fn spawn_sudp_local_session(
    client_addr: String,
    local_addr: String,
    proxy_name: String,
    mut inbound: mpsc::Receiver<Vec<u8>>,
    out_tx: mpsc::Sender<Message>,
) {
    tokio::spawn(async move {
        let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(socket) => socket,
            Err(e) => {
                log::error!("sudp: bind local udp socket failed: {}", e);
                return;
            }
        };
        if let Err(e) = socket.connect(&local_addr).await {
            log::error!("sudp: connect local udp {} failed: {}", local_addr, e);
            return;
        }

        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                payload = inbound.recv() => {
                    let Some(data) = payload else { break };
                    if let Err(e) = socket.send(&data).await {
                        log::debug!("sudp: send to local {} failed: {}", local_addr, e);
                        break;
                    }
                }
                received = socket.recv(&mut buf) => {
                    match received {
                        Ok(n) => {
                            let msg = Message::UdpPacket(rust_frp_core::UdpPacketMsg {
                                proxy_name: proxy_name.clone(),
                                data: buf[..n].to_vec(),
                                client_addr: Some(client_addr.clone()),
                            });
                            if out_tx.send(msg).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            log::debug!("sudp: recv from local {} failed: {}", local_addr, e);
                            break;
                        }
                    }
                }
            }
        }
    });
}

/// sudp 访问者会话上下文（跨会话共享的不可变信息）
#[derive(Clone)]
pub(super) struct SudpVisitorContext {
    proxy_name: String,
    run_id: String,
    config: Arc<ClientConfig>,
    work_conn_tls: bool,
    /// 服务器下发的工作连接端口（0 = 旧版服务端未下发，按本地推算）
    server_work_conn_port: u16,
    secret_key: String,
    use_encryption: bool,
    use_compression: bool,
    stcp_tx: mpsc::Sender<Message>,
    socket: Arc<tokio::net::UdpSocket>,
}

/// sudp 访问者：监听本地 UDP 端口，按源地址建立独立隧道会话
pub(super) async fn start_sudp_visitor(
    bind_addr: String,
    proxy_name: String,
    stcp_tx: mpsc::Sender<Message>,
    run_id: String,
    config: Arc<ClientConfig>,
    work_conn_tls: bool,
    server_work_conn_port: u16,
) {
    // UDP 无 TIME_WAIT 问题，但仍需重试：旧任务 abort 释放端口与本次
    // bind 之间存在竞态窗口，一次失败就 return 会让 sudp 隧道静默消失
    let socket = loop {
        match tokio::net::UdpSocket::bind(&bind_addr).await {
            Ok(socket) => break Arc::new(socket),
            Err(e) => {
                log::warn!(
                    "Failed to bind sudp visitor {} on {}: {:?}, retrying in 1s",
                    proxy_name,
                    bind_addr,
                    e
                );
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    };
    log::info!("sudp visitor for {} listening on {}", proxy_name, bind_addr);

    let visitor_cfg = config.visitors.iter().find(|v| v.server_name == proxy_name);
    let ctx = SudpVisitorContext {
        secret_key: visitor_cfg
            .and_then(|v| v.secret_key.clone())
            .unwrap_or_default(),
        use_encryption: visitor_cfg.map(|v| v.use_encryption).unwrap_or(false),
        use_compression: visitor_cfg.map(|v| v.use_compression).unwrap_or(false),
        proxy_name,
        run_id,
        config,
        work_conn_tls,
        server_work_conn_port,
        stcp_tx,
        socket: socket.clone(),
    };

    let sessions: SudpSessions = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let mut buf = vec![0u8; 65535];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, src)) => {
                let data = buf[..n].to_vec();
                let existing = { sessions.lock().await.get(&src).cloned() };
                let inbound = match existing {
                    Some(tx) => tx,
                    None => match sudp_open_session(&ctx, src, sessions.clone()).await {
                        Ok(tx) => {
                            sessions.lock().await.insert(src, tx.clone());
                            tx
                        }
                        Err(e) => {
                            log::warn!("sudp visitor session for {} failed: {}", src, e);
                            continue;
                        }
                    },
                };
                if inbound.send(data).await.is_err() {
                    sessions.lock().await.remove(&src);
                }
            }
            Err(e) => {
                log::error!("sudp visitor recv error: {:?}", e);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// 打开一个 sudp 访问者隧道会话
///
/// 先向服务端登记访问请求（服务端据此创建桥接并通知代理侧建工作连接），
/// 再建立工作连接。会话在读循环退出（隧道关闭或心跳超时）时自行从
/// `sessions` 中摘除，避免陈旧会话常驻。
pub(super) async fn sudp_open_session(
    ctx: &SudpVisitorContext,
    src: SocketAddr,
    sessions: SudpSessions,
) -> Result<mpsc::Sender<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    // 与服务端代理 secret_key 一致的访问签名（服务端 fail-closed 校验）
    let bridge_id = rust_frp_util::rand_id(24);
    let timestamp = get_timestamp();
    let sign_key = rust_frp_auth::generate_stcp_visitor_sign_key(
        &ctx.secret_key,
        &ctx.proxy_name,
        &bridge_id,
        &ctx.run_id,
        timestamp,
    );

    // 先注册应答等待者再发送：服务端可能在控制消息写出前就处理完建桥，
    // 后注册会永久错过 StcpVisitorResp（oneshot 值已缓冲则无此忧）。
    // 同 STCP：句柄析构即反注册，超时/失败不留 dead sender
    let waiter = StcpRespRegistry::global().register(&bridge_id);
    ctx.stcp_tx
        .send(Message::StcpVisitor(rust_frp_core::StcpVisitorMsg {
            proxy_name: ctx.proxy_name.clone(),
            run_id: ctx.run_id.clone(),
            bridge_id: bridge_id.clone(),
            timestamp,
            sign_key,
        }))
        .await
        .map_err(|e| format!("Failed to send StcpVisitor for sudp: {}", e))?;

    // 等待服务端桥就绪确认（StcpVisitorResp）再拨工作连接——与 STCP visitor
    // 同一竞态防护：桥未建立时工作连接先到会被当作普通代理连接池化丢弃，
    // 会话永远等不到数据（对齐 handle_stcp_visitor_conn / 上游 8146c08）。
    let grant = match waiter
        .wait_timeout(std::time::Duration::from_secs(10))
        .await
    {
        Ok(Ok(grant)) => {
            if grant.bridge_id != bridge_id {
                return Err("SUDP visitor response bridge mismatch".into());
            }
            grant
        }
        Ok(Err(e)) => return Err(format!("SUDP visitor rejected by server: {}", e).into()),
        Err(StcpWaitError::Dropped) => {
            return Err("SUDP visitor waiter dropped (reconnect?)".into())
        }
        Err(StcpWaitError::Timeout) => {
            return Err(format!(
                "timeout waiting for SUDP visitor resp of {} (bridge not ready)",
                ctx.proxy_name
            )
            .into())
        }
    };

    let (work_conn, _, _) = open_work_conn(
        &ctx.config,
        WorkConnRequest {
            proxy_name: &ctx.proxy_name,
            run_id: &ctx.run_id,
            work_conn_tls: ctx.work_conn_tls,
            session: None,
            server_work_conn_port: ctx.server_work_conn_port,
            use_encryption: ctx.use_encryption,
            use_compression: ctx.use_compression,
            bridge_id: &bridge_id,
            bridge_sign_key: &grant.work_conn_sign_key,
        },
    )
    .await?;

    log::info!(
        "sudp visitor tunnel established for {} (client {})",
        ctx.proxy_name,
        src
    );

    let (mut reader, writer) = tokio::io::split(work_conn);
    let out_tx = spawn_tunnel_writer(writer);

    // 出站：本地 UDP 载荷 → UDP 包帧（会话与源地址一一对应，故回程目标固定为 src）
    let (inbound_tx, mut inbound_rx) = mpsc::channel::<Vec<u8>>(256);
    {
        let proxy_name = ctx.proxy_name.clone();
        tokio::spawn(async move {
            while let Some(data) = inbound_rx.recv().await {
                let msg = Message::UdpPacket(rust_frp_core::UdpPacketMsg {
                    proxy_name: proxy_name.clone(),
                    data,
                    client_addr: Some(src.to_string()),
                });
                if out_tx.send(msg).await.is_err() {
                    break;
                }
            }
        });
    }

    // 入站：隧道 → 本地访问者；60s 无消息（含心跳）即判定会话结束
    let socket = ctx.socket.clone();
    let proxy_name = ctx.proxy_name.clone();
    tokio::spawn(async move {
        loop {
            let received = tokio::time::timeout(
                SUDP_TUNNEL_IDLE_TIMEOUT,
                rust_frp_core::read_message(&mut reader),
            )
            .await;
            match received {
                Ok(Ok(Message::UdpPacket(packet))) => {
                    if let Err(e) = socket.send_to(&packet.data, src).await {
                        log::debug!("sudp visitor send_to {} failed: {}", src, e);
                    }
                }
                // Ping 等控制消息不转发
                Ok(Ok(_)) => continue,
                Ok(Err(e)) => {
                    log::debug!("sudp visitor tunnel closed for {}: {:?}", proxy_name, e);
                    break;
                }
                Err(_) => {
                    log::debug!("sudp visitor tunnel idle timeout for {}", proxy_name);
                    break;
                }
            }
        }
        sessions.lock().await.remove(&src);
        log::info!("sudp visitor session for {} closed", src);
    });

    Ok(inbound_tx)
}
