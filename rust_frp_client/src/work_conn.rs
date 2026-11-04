//! 从 lib.rs 拆出的 work_conn 实现。

use super::*;

/// 生成工作连接签名密钥（与服务端 AuthManager::generate_work_conn_sign_key 一致）
/// 解析登录所用的认证令牌
///
/// - `auth.method = "token"`：返回配置中的静态 token（缺省为空串）
/// - `auth.method = "oidc"`：向 IdP 的令牌端点以 `client_credentials` 换取
///   `access_token`；每次登录/重连都重新获取，避免复用已过期的令牌
pub(super) async fn resolve_auth_token(
    config: &ClientConfig,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    if config.auth.method != "oidc" {
        return Ok(config.auth.token.clone().unwrap_or_default());
    }
    let oidc = config.auth.oidc.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "auth.oidc is required when auth.method = \"oidc\"",
        )
    })?;
    let token = rust_frp_auth::OidcClientCredentials::new(oidc)
        .fetch_access_token()
        .await
        .map_err(|e| format!("failed to obtain OIDC access token: {e}"))?;
    log::info!(
        "Obtained OIDC access token for login (expires_in={}s)",
        token.expires_in
    );
    Ok(token.access_token)
}

/// 解析 `auth.tokenSource` 并把结果写入内存中的 `auth.token`
///
/// 在客户端构造与配置重载时各调用一次。解析结果只存在于内存，不写回磁盘；
/// 之后的登录（[`resolve_auth_token`]）、工作连接签名与应用层加密都统一读取
/// `auth.token`，因此无需改动这些热路径。
pub(super) fn apply_token_source(
    config: &mut ClientConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(ts) = config.auth.token_source.clone() else {
        return Ok(());
    };
    let token = match ts.r#type.as_str() {
        "file" => {
            let path = ts.file_path.as_deref().ok_or_else(|| {
                "auth.tokenSource.filePath is required when type = \"file\"".to_string()
            })?;
            std::fs::read_to_string(path)
                .map_err(|e| format!("failed to read auth.tokenSource.filePath {path}: {e}"))?
                .trim()
                .to_string()
        }
        "exec" => {
            let argv = ts.exec.as_ref().ok_or_else(|| {
                "auth.tokenSource.exec is required when type = \"exec\"".to_string()
            })?;
            let (prog, args) = argv
                .split_first()
                .ok_or_else(|| "auth.tokenSource.exec must not be empty".to_string())?;
            let output = std::process::Command::new(prog)
                .args(args)
                .output()
                .map_err(|e| format!("failed to run auth.tokenSource.exec {prog}: {e}"))?;
            if !output.status.success() {
                return Err(
                    format!("auth.tokenSource.exec {prog} exited with {}", output.status).into(),
                );
            }
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        other => {
            return Err(format!(
                "unsupported auth.tokenSource.type: {other} (expected \"file\" or \"exec\")"
            )
            .into());
        }
    };
    if token.is_empty() {
        return Err("auth.tokenSource produced an empty token".into());
    }
    log::info!(
        "Resolved auth.tokenSource (type={}) into an in-memory token",
        ts.r#type
    );
    config.auth.token = Some(token);
    Ok(())
}

pub(super) fn generate_work_conn_sign_key(token: &str, run_id: &str) -> String {
    use ring::{digest, hmac};
    // encryption_key = SHA-256(token)
    let mut hasher = digest::Context::new(&digest::SHA256);
    hasher.update(token.as_bytes());
    let encryption_key = hasher.finish();

    // sign_key = HMAC-SHA256(encryption_key, "work_conn:{run_id}")
    let msg = format!("work_conn:{}", run_id);
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, encryption_key.as_ref());
    let tag = hmac::sign(&hmac_key, msg.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(tag.as_ref())
}

pub(super) fn work_conn_disconnect_is_retryable(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    [
        "connection reset",
        "connection aborted",
        "broken pipe",
        "unexpectedeof",
        "early eof",
        "close_notify",
        "half-close grace",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}

/// 派生应用层加密密钥（SHA-256(token)，与服务端 AuthManager::generate_encryption_key 一致）
pub(super) fn derive_encryption_key(token: &str) -> Vec<u8> {
    use ring::digest;
    let mut hasher = digest::Context::new(&digest::SHA256);
    hasher.update(token.as_bytes());
    hasher.finish().as_ref().to_vec()
}

/// 工作连接建立参数（收敛参数列表，避免长参数签名）
pub(super) struct WorkConnRequest<'a> {
    pub(super) proxy_name: &'a str,
    pub(super) run_id: &'a str,
    pub(super) work_conn_tls: bool,
    /// `Some` 时可作为回退路径：经多路复用会话流建立（tcp_mux / QUIC，协议与直连工作端口一致）
    pub(super) session: Option<&'a Arc<dyn Session>>,
    /// 服务器 LoginResp 下发的工作连接端口（0 = 未下发，按客户端配置/默认推算）
    pub(super) server_work_conn_port: u16,
    pub(super) use_encryption: bool,
    pub(super) use_compression: bool,
    /// STCP/SUDP/XTCP 回退桥 ID；普通代理为空
    pub(super) bridge_id: &'a str,
    /// 服务端下发的角色签名；普通代理为空
    pub(super) bridge_sign_key: &'a str,
}

/// 打开工作连接并完成握手后的结果
///
/// 元组为 `(连接, 服务器观测到的访问者 IP, 访问者端口)`；后两项供
/// PROXY protocol v1 头使用。
pub(super) type OpenedWorkConn = (Box<dyn rust_frp_net::FrpConn>, String, u16);

pub(super) struct WorkConnEstablishRequest<'a> {
    pub(super) proxy_name: &'a str,
    pub(super) run_id: &'a str,
    pub(super) bridge_id: &'a str,
    pub(super) bridge_sign_key: &'a str,
    pub(super) work_conn_tls: bool,
    pub(super) server_work_conn_port: u16,
    pub(super) session: Option<&'a Arc<dyn Session>>,
}

/// 直拨服务器专用工作端口（数据/控制分离的数据面通道）
///
/// - 端口：`resolve_work_conn_port`（服务器下发 > 客户端配置 > server_port+1000）；
/// - 超时：TCP 连接 5 秒（auto 模式下快速失败以触发 mux 回退，也防 DROP 型
///   防火墙把工作连接建立挂死）；
/// - TLS：服务器协商要求时复用控制连接的客户端 TLS 配置。
pub(super) async fn dial_work_port(
    config: &ClientConfig,
    server_work_conn_port: u16,
    work_conn_tls: bool,
    proxy_name: &str,
) -> Result<Box<dyn rust_frp_net::FrpConn>, Box<dyn std::error::Error + Send + Sync>> {
    let work_addr = format!(
        "{}:{}",
        config.server_addr,
        resolve_work_conn_port(config, server_work_conn_port)
    );
    let tcp_conn = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect(&work_addr),
    )
    .await
    .map_err(|_| format!("connect to work port {} timed out (5s)", work_addr))??;

    // 预建的工作连接（pool_count > 0）会长期空闲，必须靠 keepalive 让内核
    // 定期探测，否则云上 NAT 会在 5~10 分钟内静默回收，连接池随后拿着死连接
    // 去桥接，表现为「偶发首个请求失败 / 502」。
    if let Some(idle) = config.transport.tcp_keepalive_idle() {
        if let Err(e) = rust_frp_net::apply_tcp_keepalive(&tcp_conn, idle) {
            log::debug!("set TCP keepalive on work conn failed: {}", e);
        }
    }
    log::info!(
        "Connected to server work conn port: {} (proxy {})",
        work_addr,
        proxy_name
    );

    if work_conn_tls {
        let tls_config = build_client_tls_config(config)
            .map_err(|e| format!("failed to build client TLS config: {}", e))?
            .ok_or("server requires TLS work conn but client tls is disabled")?;
        let tls_stream = tls_config
            .connect(&config.server_addr, tcp_conn)
            .await
            .map_err(|e| format!("work conn TLS handshake failed: {}", e))?;
        log::info!("Work conn TLS established for proxy: {}", proxy_name);
        Ok(Box::new(tls_stream))
    } else {
        Ok(Box::new(tcp_conn))
    }
}

/// 打开一条到服务端的工作连接并完成 `NewWorkConn`/`StartWorkConn` 握手
///
/// 返回的连接在需要时已按固定顺序包装：**先压缩（内层）、后加密（外层）**，
/// 与服务器 [`rust_frp_server`] 及对端客户端保持一致。直连与 tcp_mux 两条
/// 路径共用本函数（握手消息明文，包装在握手之后）。
///
/// # 路径选择（`transport.work_conn_via`）
///
/// - `auto`（默认）：**优先直拨专用工作端口**（数据/控制分离，高吞吐不挤占
///   控制通道）；直拨失败且有 mux 会话时自动回退会话流，并记入 60 秒降级
///   缓存（期间不再尝试直拨，超时后自动重试）。无会话可回退（STCP/XTCP
///   visitor 等）则直拨失败即报错。
/// - `mux`：始终走会话流；无会话时退回直拨。
/// - `dedicated`：强制直拨，失败即报错，不回退。
pub(super) async fn open_work_conn(
    config: &ClientConfig,
    req: WorkConnRequest<'_>,
) -> Result<OpenedWorkConn, Box<dyn std::error::Error + Send + Sync>> {
    let WorkConnRequest {
        proxy_name,
        run_id,
        work_conn_tls,
        session,
        server_work_conn_port,
        use_encryption,
        use_compression,
        bridge_id,
        bridge_sign_key,
    } = req;

    let via = config.transport.work_conn_via.to_ascii_lowercase();
    let prefer_direct = match via.as_str() {
        "mux" => false,
        "dedicated" => true,
        _ => {
            // auto：仅 TCP 控制连接才有"另一个端口"可拨；
            // QUIC/KCP 等传输工作连接天然与会话同通道，保持原行为
            config.transport.protocol == "tcp" && work_port_currently_preferred()
        }
    };

    let mut work_conn: Box<dyn rust_frp_net::FrpConn> = if prefer_direct {
        match dial_work_port(config, server_work_conn_port, work_conn_tls, proxy_name).await {
            Ok(conn) => {
                mark_work_port_ok();
                conn
            }
            Err(dial_err) if via == "dedicated" => return Err(dial_err),
            Err(dial_err) => match session {
                Some(session) => {
                    // 数据/控制分离不可用 → 回退 mux 会话流（连通性优先）
                    mark_work_port_failed();
                    log::warn!(
                        "Work port dial failed for proxy {} ({}), falling back to mux session",
                        proxy_name,
                        dial_err
                    );
                    let stream = session.open_stream().await.map_err(|e| {
                        format!(
                            "both work port ({}) and mux session failed: {}",
                            dial_err, e
                        )
                    })?;
                    log::info!(
                        "Mux work stream established (fallback) for proxy: {}",
                        proxy_name
                    );
                    stream
                }
                None => return Err(dial_err),
            },
        }
    } else if let Some(session) = session {
        // 多路复用（tcp_mux / QUIC）：工作连接 = 会话流（服务端分发循环经
        // process_work_conn 处理，协议与直连工作端口完全一致）
        let stream = session
            .open_stream()
            .await
            .map_err(|e| format!("session open work stream failed: {}", e))?;
        log::info!("Mux work stream established for proxy: {}", proxy_name);
        stream
    } else {
        // 无会话可用（STCP/XTCP visitor 的 owner/访问者腿等）：直拨工作端口
        dial_work_port(config, server_work_conn_port, work_conn_tls, proxy_name).await?
    };

    // 生成 sign_key
    let sign_key = config
        .auth
        .token
        .as_ref()
        .map(|token| generate_work_conn_sign_key(token, run_id))
        .unwrap_or_default();

    // 发送 NewWorkConn 消息
    let new_work_conn_msg = NewWorkConnMsg {
        run_id: run_id.to_string(),
        proxy_name: proxy_name.to_string(),
        timestamp: get_timestamp(),
        sign_key,
        bridge_id: bridge_id.to_string(),
        bridge_sign_key: bridge_sign_key.to_string(),
        use_encryption,
        use_compression,
    };
    rust_frp_core::write_message(&mut work_conn, &Message::NewWorkConn(new_work_conn_msg)).await?;

    // 等待 StartWorkConn 响应
    let (src_addr, src_port) = match rust_frp_core::read_message(&mut work_conn).await? {
        Message::StartWorkConn(start_msg) => {
            if !start_msg.error.is_empty() {
                return Err(format!("Server error: {}", start_msg.error).into());
            }
            log::info!("Work conn established for proxy: {}", proxy_name);
            (start_msg.src_addr, start_msg.src_port)
        }
        _ => {
            return Err("Unexpected response from server".into());
        }
    };

    // 应用层压缩与加密：握手完成后按固定顺序包装 —— 先压缩（内层）、后加密（外层）
    if use_compression {
        work_conn = Box::new(rust_frp_net::compress::CompressedStream::new(work_conn));
        log::info!(
            "Work conn application-layer compression (snappy) enabled for proxy: {}",
            proxy_name
        );
    }
    if use_encryption {
        let token = config
            .auth
            .token
            .as_deref()
            .ok_or("use_encryption requires a configured token")?;
        let key = derive_encryption_key(token);
        work_conn = Box::new(rust_frp_net::crypto::EncryptedStream::new(work_conn, &key)?);
        log::info!(
            "Work conn application-layer encryption (AES-256-GCM) enabled for proxy: {}",
            proxy_name
        );
    }

    Ok((work_conn, src_addr, src_port))
}

/// 建立工作连接（独立函数，供 ClientControl::run 调用）
///
/// - 多路复用：tcp_mux 会话存在时直接打开会话流（无需新建 TCP，TLS 在会话层）
/// - 端口：优先使用客户端配置的 work_conn_port，默认 server_port + 1000
/// - TLS：服务器通过 LoginRespMsg.work_conn_tls 协商后按需 TLS 加密
pub(super) async fn establish_work_connection(
    config: &ClientConfig,
    req: WorkConnEstablishRequest<'_>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let WorkConnEstablishRequest {
        proxy_name,
        run_id,
        bridge_id,
        bridge_sign_key,
        work_conn_tls,
        server_work_conn_port,
        session,
    } = req;
    // 查找代理配置
    let proxy_config = config
        .proxies
        .iter()
        .find(|p| p.name == proxy_name)
        .ok_or_else(|| format!("Proxy config not found: {}", proxy_name))?;

    // 应用层加密（fail-closed）：启用 use_encryption 必须已配置 token 以派生密钥
    let use_encryption = proxy_config.use_encryption;
    let use_compression = proxy_config.use_compression;
    if use_encryption && config.auth.token.is_none() {
        return Err(format!(
            "proxy [{}] enables use_encryption but client has no token configured",
            proxy_name
        )
        .into());
    }

    let (work_conn, src_addr, src_port) = open_work_conn(
        config,
        WorkConnRequest {
            proxy_name,
            run_id,
            work_conn_tls,
            session,
            server_work_conn_port,
            use_encryption,
            use_compression,
            bridge_id,
            bridge_sign_key,
        },
    )
    .await?;

    // sudp 代理：工作连接上承载 UDP 包帧（不连接本地 TCP 服务）
    if proxy_config.r#type == "sudp" {
        let local_addr = format!("{}:{}", proxy_config.local_ip, proxy_config.local_port);
        return serve_sudp_proxy(work_conn, proxy_name, local_addr).await;
    }

    // 连接到本地服务
    let local_addr = format!("{}:{}", proxy_config.local_ip, proxy_config.local_port);
    let mut local_conn = tokio::net::TcpStream::connect(&local_addr).await?;
    log::info!("Connected to local service: {}", local_addr);

    // 如果启用了 PROXY protocol，先写入 header 再桥接
    // 版本语义对齐原版：显式 proxyProtocolVersion 优先（v1/v2），
    // 未设置版本时默认 v1；仅设置版本不设 proxy_protocol 也视为启用。
    let pp_version = proxy_config.proxy_protocol_version.as_deref();
    let proxy_protocol_enabled =
        proxy_config.proxy_protocol.unwrap_or(false) || pp_version.is_some();
    if proxy_protocol_enabled && src_port > 0 {
        let version = pp_version.unwrap_or("v1");
        let header = rust_frp_net::proxy_protocol::build_proxy_protocol_header(
            &src_addr,
            src_port,
            &proxy_config.local_ip,
            proxy_config.local_port,
            version,
        );
        log::info!(
            "Writing PROXY protocol {} header for {}: {} bytes",
            version,
            proxy_name,
            header.len()
        );
        tokio::io::AsyncWriteExt::write_all(&mut local_conn, &header).await?;
    }

    // 双向桥接工作连接和本地连接
    rust_frp_util::bridge_streams(work_conn, local_conn).await?;
    Ok(())
}

// ============ XTCP P2P 打洞（STUN + UDP hole punching + KCP 通道） ============

/// STUN 探测公网端点；失败返回 None（上层回退/留空，由服务器观察地址兜底）
pub(super) async fn stun_discover(socket: &Arc<tokio::net::UdpSocket>) -> Option<SocketAddr> {
    let servers = rust_frp_net::default_stun_socket_addrs().await;
    if servers.is_empty() {
        log::warn!("STUN: no servers resolved (DNS failed?)");
        return None;
    }
    match rust_frp_net::discover_public_endpoint(socket.clone(), &servers).await {
        Ok(addr) => {
            log::info!("STUN discovered public endpoint: {}", addr);
            Some(addr)
        }
        Err(e) => {
            log::warn!("STUN discovery failed: {}", e);
            None
        }
    }
}

/// 本机局域网 IPv4（UDP connect 技巧，只设置默认目标不实际发包）
pub(super) async fn detect_local_ip() -> Option<std::net::Ipv4Addr> {
    let s = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    s.connect("8.8.8.8:80").await.ok()?;
    match s.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) => Some(v4),
        _ => None,
    }
}

/// 打洞 socket 的本地端点字符串（局域网 IP + 端口），同 NAT 下直连用
pub(super) async fn local_endpoint_of(socket: &tokio::net::UdpSocket) -> String {
    let port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
    match detect_local_ip().await {
        Some(ip) => format!("{}:{}", ip, port),
        None => String::new(),
    }
}

/// 解析对端候选地址（公网优先，本地其次），去重、忽略空串
pub(super) fn parse_peer_addrs(public: &str, local: &str) -> Vec<SocketAddr> {
    let mut peers = Vec::new();
    for s in [public, local] {
        if !s.is_empty() {
            if let Ok(a) = s.parse::<SocketAddr>() {
                if !peers.contains(&a) {
                    peers.push(a);
                }
            }
        }
    }
    peers
}

/// 等待 KCP 会话激活（收到对端有效输入 = 打洞成功）
pub(super) async fn wait_kcp_active(stream: &KcpStream, timeout: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if stream.has_activity() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    stream.has_activity()
}
