//! 从 lib.rs 拆出的 visitor 实现。

use super::*;

/// XTCP owner（proxy 提供方）打洞流程：
///
/// 1. 绑定 UDP socket（与 STUN 探测复用，保证 NAT 映射一致）
/// 2. STUN 探测公网地址，回送 `XtcpNatInfo` 给 visitor
/// 3. `KcpStream::accept` 等待 visitor 打洞（punch 包双向打通 NAT）
/// 4. 成功后连接本地被代理服务并桥接；超时/失败静默返回，
///    visitor 侧会回退 STCP 服务器中继
pub(super) async fn run_xtcp_owner(
    proxy: rust_frp_config::ProxyConfig,
    visitor_public: String,
    visitor_local: String,
    msg_tx: tokio::sync::mpsc::Sender<Message>,
    run_id: String,
) {
    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            log::error!("XTCP owner bind UDP failed: {}", e);
            return;
        }
    };
    let public = stun_discover(&socket).await;
    let local_addr = local_endpoint_of(&socket).await;

    // 回送自己的 NAT info（owner 侧无需 secret_key 签名，服务端仅校验 visitor 侧）
    let nat_info = rust_frp_core::XtcpNatInfoMsg {
        proxy_name: proxy.name.clone(),
        run_id,
        nat_type: "unknown".to_string(),
        local_addr: local_addr.clone(),
        public_addr: public.as_ref().map(|a| a.to_string()).unwrap_or_default(),
        sign_key: String::new(),
        timestamp: 0,
    };
    if let Err(e) = msg_tx.send(Message::XtcpNatInfo(nat_info)).await {
        log::error!("XTCP owner failed to send NAT info: {}", e);
        return;
    }

    let peers = parse_peer_addrs(&visitor_public, &visitor_local);
    if peers.is_empty() {
        log::warn!(
            "XTCP owner: no valid visitor addresses for proxy {}",
            proxy.name
        );
        return;
    }

    let stream = match KcpStream::accept(socket, peers).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("XTCP owner kcp accept failed: {}", e);
            return;
        }
    };

    log::info!(
        "XTCP owner: waiting for hole punch from visitor for proxy {}",
        proxy.name
    );
    if !wait_kcp_active(&stream, std::time::Duration::from_secs(6)).await {
        log::info!(
            "XTCP owner: hole punch timeout for {}, visitor will fall back to STCP relay",
            proxy.name
        );
        return;
    }
    log::info!("XTCP P2P established for {} (owner side)", proxy.name);

    // 连接本地被代理服务
    let local_svc = format!("{}:{}", proxy.local_ip, proxy.local_port);
    let local_conn = match tokio::net::TcpStream::connect(&local_svc).await {
        Ok(c) => c,
        Err(e) => {
            log::error!(
                "XTCP owner connect local service {} failed: {}",
                local_svc,
                e
            );
            return;
        }
    };

    if let Err(e) = rust_frp_util::bridge_streams(stream, local_conn).await {
        log::debug!("XTCP owner bridge ended: {}", e);
    }
}

/// XTCP visitor 打洞尝试：
///
/// 返回 `None` 表示 P2P 成功（local_conn 已与 KCP 流桥接）；
/// 返回 `Some(local_conn)` 表示打洞失败，调用方继续走 STCP 服务器中继。
pub(super) async fn xtcp_try_p2p(
    proxy_name: &str,
    msg_tx: &tokio::sync::mpsc::Sender<Message>,
    run_id: &str,
    secret_key: &str,
    registry: &XtcpRegistry,
    local_conn: tokio::net::TcpStream,
) -> Option<tokio::net::TcpStream> {
    // 1. 绑定 UDP socket（与 STUN 探测复用）
    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            log::warn!("XTCP visitor bind UDP failed: {}", e);
            return Some(local_conn);
        }
    };
    let public = stun_discover(&socket).await;
    let local_addr = local_endpoint_of(&socket).await;

    // 2. 注册等待 owner 回传地址
    let addr_rx = registry.register(proxy_name.to_string());

    // 3. 发送自己的 NAT info（携带 secret_key 签名，服务端校验 visitor 身份）
    let timestamp = get_timestamp();
    let sign_key = rust_frp_auth::generate_stcp_sign_key(secret_key, proxy_name, timestamp);
    let nat_info = rust_frp_core::XtcpNatInfoMsg {
        proxy_name: proxy_name.to_string(),
        run_id: run_id.to_string(),
        nat_type: "unknown".to_string(),
        local_addr,
        public_addr: public.as_ref().map(|a| a.to_string()).unwrap_or_default(),
        sign_key,
        timestamp,
    };
    if msg_tx.send(Message::XtcpNatInfo(nat_info)).await.is_err() {
        log::warn!("XTCP visitor: control channel closed, falling back");
        return Some(local_conn);
    }

    // 4. 等待 owner 的 NAT info（经服务器中继）
    let (owner_public, owner_local) =
        match tokio::time::timeout(std::time::Duration::from_secs(6), addr_rx).await {
            Ok(Ok(addrs)) => addrs,
            Ok(Err(_)) => {
                log::info!("XTCP visitor: pending session replaced, falling back");
                return Some(local_conn);
            }
            Err(_) => {
                log::info!(
                    "XTCP visitor: no owner NAT info in time for {}, falling back",
                    proxy_name
                );
                return Some(local_conn);
            }
        };

    let peers = parse_peer_addrs(&owner_public, &owner_local);
    if peers.is_empty() {
        log::info!(
            "XTCP visitor: owner has no reachable addresses for {}, falling back",
            proxy_name
        );
        return Some(local_conn);
    }

    // 5. 发起 KCP 打洞（connect 侧随机 conv，punch 包周期发送）
    log::info!(
        "XTCP visitor: hole punching for {} (peers: {:?})",
        proxy_name,
        peers
    );
    let conv = rand::random::<u32>();
    let stream = match KcpStream::connect(socket, peers, conv).await {
        Ok(s) => s,
        Err(e) => {
            log::warn!("XTCP visitor kcp connect failed: {}", e);
            return Some(local_conn);
        }
    };

    if !wait_kcp_active(&stream, std::time::Duration::from_secs(6)).await {
        log::info!(
            "XTCP visitor: hole punch timeout for {}, falling back to STCP relay",
            proxy_name
        );
        return Some(local_conn);
    }
    log::info!("XTCP P2P established for {} (visitor side)", proxy_name);

    // 6. P2P 桥接：本地连接 <-> KCP 流
    if let Err(e) = rust_frp_util::bridge_streams(stream, local_conn).await {
        log::debug!("XTCP visitor bridge ended: {}", e);
    }
    None
}

/// STCP/XTCP visitor 参数集（收敛 8 个独立参数，避免顺序误用——同 ClientControlDeps 惯例）
#[derive(Clone)]
pub(super) struct StcpVisitorDeps {
    pub(super) bind_addr: String,
    pub(super) proxy_name: String,
    pub(super) stcp_tx: mpsc::Sender<Message>,
    pub(super) run_id: String,
    pub(super) config: Arc<ClientConfig>,
    pub(super) work_conn_tls: bool,
    /// 服务器下发的工作连接端口（0 = 旧版服务端未下发，按本地推算）
    pub(super) server_work_conn_port: u16,
    pub(super) xtcp_registry: Arc<XtcpRegistry>,
}

/// 单次尝试绑定 visitor 本地监听端口。
///
/// 显式设置 `SO_REUSEADDR`：重连时上一轮会话的 accepted 连接关闭后会进入
/// `TIME_WAIT`（本地地址正是监听端口），未设置 REUSEADDR 的 bind 在 Linux
/// 上最长要等约 60s 才能成功（Windows 上 std 默认已开，行为对齐 frp 原版
/// ——Go 的 net.Listen 默认也开）。注意 REUSEADDR 只允许复用 TIME_WAIT，
/// 仍活动的监听端口一样会 AddrInUse，由调用方的重试循环处理。
pub(super) async fn try_bind_visitor_listener(
    bind_addr: &str,
) -> std::io::Result<tokio::net::TcpListener> {
    let mut last_err: Option<std::io::Error> = None;
    for addr in tokio::net::lookup_host(bind_addr).await? {
        let socket = if addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        socket.set_reuseaddr(true)?;
        match socket.bind(addr).and_then(|()| socket.listen(1024)) {
            Ok(l) => return Ok(l),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("no address resolved for {}", bind_addr),
        )
    }))
}

/// 绑定 visitor 本地监听端口，失败按 1s 间隔无限重试。
///
/// 直接 return 是血的教训：曾经 bind 失败一次（旧 listener 未释放）任务
/// 就退出，隧道再也不监听，只能手动重启 frpc。abort+await 已保证旧
/// listener 关闭，这里的重试兜住 TIME_WAIT 与瞬时 EMFILE 等残余竞态。
pub(super) async fn bind_visitor_listener(bind_addr: &str) -> tokio::net::TcpListener {
    loop {
        match try_bind_visitor_listener(bind_addr).await {
            Ok(l) => return l,
            Err(e) => {
                log::warn!(
                    "Failed to bind visitor listener on {}: {:?}, retrying in 1s",
                    bind_addr,
                    e
                );
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
}

/// 启动 STCP/XTCP 访问者：监听本地端口，当有连接时创建到服务器的工作连接并桥接
pub(super) async fn start_stcp_visitor(deps: StcpVisitorDeps) {
    let StcpVisitorDeps {
        bind_addr,
        proxy_name,
        stcp_tx,
        run_id,
        config,
        work_conn_tls,
        server_work_conn_port,
        xtcp_registry,
    } = deps;
    let listener = bind_visitor_listener(&bind_addr).await;
    log::info!("STCP visitor for {} listening on {}", proxy_name, bind_addr);

    loop {
        match listener.accept().await {
            Ok((local_conn, addr)) => {
                log::info!(
                    "STCP visitor accepted connection from {} for {}",
                    addr,
                    proxy_name
                );
                let deps = StcpVisitorDeps {
                    bind_addr: bind_addr.clone(),
                    proxy_name: proxy_name.clone(),
                    stcp_tx: stcp_tx.clone(),
                    run_id: run_id.clone(),
                    config: Arc::clone(&config),
                    work_conn_tls,
                    server_work_conn_port,
                    xtcp_registry: xtcp_registry.clone(),
                };
                tokio::spawn(async move {
                    if let Err(e) = handle_stcp_visitor_conn(local_conn, deps).await {
                        log::error!("STCP visitor connection error: {:?}", e);
                    }
                });
            }
            Err(e) => {
                log::error!("STCP visitor accept error: {:?}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }
}

/// 处理单个 STCP/XTCP 访问者连接
/// XTCP 先走 STUN + KCP UDP 打洞尝试 P2P；失败/超时后回退 STCP 服务端中继
pub(super) async fn handle_stcp_visitor_conn(
    local_conn: tokio::net::TcpStream,
    deps: StcpVisitorDeps,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let StcpVisitorDeps {
        proxy_name,
        stcp_tx,
        run_id,
        config,
        work_conn_tls,
        server_work_conn_port,
        xtcp_registry,
        ..
    } = deps;
    let is_xtcp = config
        .visitors
        .iter()
        .any(|v| v.server_name == proxy_name && v.r#type == "xtcp");

    // 访问者配置的 secret_key（需与服务端代理的 secret_key 一致）
    let secret_key = config
        .visitors
        .iter()
        .find(|v| v.server_name == proxy_name)
        .and_then(|v| v.secret_key.clone())
        .unwrap_or_default();

    // 应用层加密：需与对端代理的 use_encryption 配置一致（fail-closed）
    let use_encryption = config
        .visitors
        .iter()
        .find(|v| v.server_name == proxy_name)
        .map(|v| v.use_encryption)
        .unwrap_or(false);
    let use_compression = config
        .visitors
        .iter()
        .find(|v| v.server_name == proxy_name)
        .map(|v| v.use_compression)
        .unwrap_or(false);
    if use_encryption && config.auth.token.is_none() {
        return Err(format!(
            "visitor for [{}] enables use_encryption but client has no token configured",
            proxy_name
        )
        .into());
    }

    // XTCP：先尝试 P2P 打洞，成功则本地连接直接桥接到 KCP 流
    let local_conn = if is_xtcp {
        match xtcp_try_p2p(
            &proxy_name,
            &stcp_tx,
            &run_id,
            &secret_key,
            &xtcp_registry,
            local_conn,
        )
        .await
        {
            None => return Ok(()), // P2P 成功，桥接已在内部完成
            Some(conn) => {
                log::info!(
                    "XTCP P2P unavailable for {}, falling back to STCP relay",
                    proxy_name
                );
                conn
            }
        }
    } else {
        local_conn
    };

    // STCP/XTCP 访问签名：基于访问者配置的 secret_key（与服务端代理 secret_key 一致）
    // sign_key = Base64(HMAC-SHA256(secret_key, "stcp:{proxy}:{bridge}:{run}:{timestamp}"))
    let bridge_id = rust_frp_util::rand_id(24);
    let timestamp = get_timestamp();
    let sign_key = rust_frp_auth::generate_stcp_visitor_sign_key(
        &secret_key,
        &proxy_name,
        &bridge_id,
        &run_id,
        timestamp,
    );

    let stcp_msg = rust_frp_core::StcpVisitorMsg {
        proxy_name: proxy_name.clone(),
        run_id: run_id.clone(),
        bridge_id: bridge_id.clone(),
        timestamp,
        sign_key,
    };

    // 先注册应答等待者再发送：控制循环可能在我们 await 之前就处理完
    // StcpVisitor 并收到 StcpVisitorResp，后注册会错过已发出的应答
    // （oneshot 值先于注册到达即永久丢失，只能等 10s 超时）。
    // 句柄析构即反注册：下面的任何提前 return 都不会留下 dead sender
    let waiter = StcpRespRegistry::global().register(&bridge_id);
    if let Err(e) = stcp_tx.send(Message::StcpVisitor(stcp_msg)).await {
        return Err(format!("Failed to send StcpVisitor: {}", e).into());
    }

    // 等待服务端桥就绪确认（StcpVisitorResp）再拨工作连接。
    // 不等的话存在竞态：工作连接先于控制消息到达服务端时桥尚未建立，
    // 该连接会被当作普通代理工作连接丢弃，visitor 永久等不到 StartWorkConn。
    let grant = match waiter
        .wait_timeout(std::time::Duration::from_secs(10))
        .await
    {
        Ok(Ok(grant)) => {
            if grant.bridge_id != bridge_id {
                return Err("STCP visitor response bridge mismatch".into());
            }
            grant
        }
        Ok(Err(e)) => return Err(format!("STCP visitor rejected by server: {}", e).into()),
        Err(StcpWaitError::Dropped) => {
            return Err("STCP visitor waiter dropped (reconnect?)".into())
        }
        Err(StcpWaitError::Timeout) => {
            return Err(format!(
                "timeout waiting for STCP visitor resp of {} (bridge not ready)",
                proxy_name
            )
            .into())
        }
    };

    // 工作连接：与 establish_work_connection 共用同一建立与包装逻辑
    // server_work_conn_port 经 LoginResp 下发链传入：服务端自定义了工作端口时，
    // visitor 与普通代理拨同一个口，不会错回 server_port+1000
    let (work_conn, _, _) = open_work_conn(
        &config,
        WorkConnRequest {
            proxy_name: &proxy_name,
            run_id: &run_id,
            work_conn_tls,
            session: None,
            server_work_conn_port,
            use_encryption,
            use_compression,
            bridge_id: &bridge_id,
            bridge_sign_key: &grant.work_conn_sign_key,
        },
    )
    .await?;

    rust_frp_util::bridge_streams(work_conn, local_conn).await?;
    Ok(())
}

// ============ SUDP：UDP over 隧道（对齐原版 frp 的 sudp 代理/访问者） ============
//
// 服务端不解析 UDP：它只按 STCP 语义把两端的工作连接配对桥接，UDP 报文由
// 两个 frpc 用 `UdpPacketMsg` 帧在 TCP 隧道上承载。代理侧把每个访问者源
// 地址映射成一个独立的本地 UDP 会话；访问者侧每个本地 UDP 源地址占用一条
// 独立隧道，并在 60s 无消息（代理侧每 30s 心跳）后回收。
