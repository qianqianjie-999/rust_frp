//! 数据/控制分离（双端口）端到端测试
//!
//! 覆盖重点：
//! 1. 服务端在 LoginResp 中下发真实工作端口（`work_conn_port`）；
//! 2. **数据面走专用工作端口**：TCP 代理的完整转发链路
//!    （访问者 → frps remote_port → 工作连接（直拨 work port）→ 本地服务 → 回程）
//!    全程走 `bind_port + 1000` 的工作端口，控制连接只承载控制消息；
//! 3. NewWorkConn 的 HMAC 签名在工作端口路径上照常校验（不因新路径而旁路认证）。

use rust_frp_auth::AuthManager;
use rust_frp_config::{AuthConfig, ProxyConfig, ServerConfig};
use rust_frp_core::{LoginMsg, Message};
use std::time::Duration;

/// 申请一个当前空闲的 TCP 端口（bind :0 后立即释放）
fn free_tcp_port() -> u16 {
    for _ in 0..50 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind tcp :0");
        let port = l.local_addr().expect("local addr").port();
        if port <= 60_000 {
            return port;
        }
    }
    panic!("no suitable free TCP port found");
}

/// 串行化测试用服务端启动，消除端口申请窗口竞争
static SERVER_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

async fn server_lock() -> tokio::sync::MutexGuard<'static, ()> {
    SERVER_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

/// 启动一个 frps（纯 TCP，token 认证，显式配置工作端口），返回控制端口
async fn start_server(token: &str) -> u16 {
    let bind_port = free_tcp_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".to_string(),
        bind_port,
        work_conn_port: Some(bind_port + 1000),
        // 测试需要注册任意 remote_port 的代理，放行常用端口段
        allow_ports: vec![rust_frp_config::PortRange {
            single: None,
            start: Some(10000),
            end: Some(65535),
        }],
        auth: AuthConfig {
            method: "token".to_string(),
            token: Some(token.to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut server = rust_frp_server::Server::new(cfg, None)
        .await
        .expect("server construct");
    tokio::spawn(async move {
        if let Err(e) = server.start().await {
            eprintln!("SERVER START ERROR: {e}");
        }
    });
    bind_port
}

/// 带显式 client_id 的登录消息（跨客户端场景必须区分 client_id，
/// 否则后登录者会按 kick_same_client 把前一条控制连接踢掉）
fn login_msg_with_client_id(token: &str, run_id: &str, client_id: &str) -> LoginMsg {
    LoginMsg {
        arch: "x86_64".to_string(),
        os: "linux".to_string(),
        hostname: "dual-port-e2e".to_string(),
        pool_count: 1,
        user: String::new(),
        client_id: client_id.to_string(),
        version: "0.1.0".to_string(),
        timestamp: rust_frp_util::get_timestamp(),
        run_id: run_id.to_string(),
        token: token.to_string(),
        metas: std::collections::HashMap::new(),
        client_spec: None,
    }
}

/// 带重试地建立控制连接并完成 v1 登录
async fn connect_and_login(
    port: u16,
    token: &str,
    run_id: &str,
) -> (tokio::net::TcpStream, rust_frp_core::LoginRespMsg) {
    connect_and_login_as(port, token, run_id, "dual-port-client").await
}

/// 同 connect_and_login，但可指定 client_id（跨客户端场景必须区分，
/// 否则后登录者按 kick_same_client 把前一条控制连接踢掉）
async fn connect_and_login_as(
    port: u16,
    token: &str,
    run_id: &str,
    client_id: &str,
) -> (tokio::net::TcpStream, rust_frp_core::LoginRespMsg) {
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    let mut conn = None;
    for _ in 0..20 {
        if let Ok(tcp) = tokio::net::TcpStream::connect(addr).await {
            conn = Some(tcp);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut conn = conn.expect("tcp connect");

    rust_frp_core::write_message(
        &mut conn,
        &Message::Login(login_msg_with_client_id(token, run_id, client_id)),
    )
    .await
    .expect("send login");
    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        rust_frp_core::read_message(&mut conn),
    )
    .await
    .expect("login resp within timeout")
    .expect("read login resp");
    match resp {
        Message::LoginResp(r) => (conn, r),
        other => panic!("expected LoginResp, got {other:?}"),
    }
}

/// 起一个本地 echo 服务（模拟被代理的本地服务），返回监听端口
async fn start_echo_server() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo");
    let port = listener.local_addr().expect("echo addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut rd, mut wr) = sock.split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });
    port
}

/// 启动一个 frps（纯 TCP，token 认证），返回（控制端口, 工作端口）
async fn start_server_with_work_port(token: &str, work_port: u16) -> (u16, u16) {
    let bind_port = free_tcp_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".to_string(),
        bind_port,
        // 自定义工作端口：刻意不等于 bind_port + 1000，验证客户端不按默认值推算
        work_conn_port: Some(work_port),
        allow_ports: vec![rust_frp_config::PortRange {
            single: None,
            start: Some(10000),
            end: Some(65535),
        }],
        auth: AuthConfig {
            method: "token".to_string(),
            token: Some(token.to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut server = rust_frp_server::Server::new(cfg, None)
        .await
        .expect("server construct");
    tokio::spawn(async move {
        if let Err(e) = server.start().await {
            eprintln!("SERVER START ERROR: {e}");
        }
    });
    (bind_port, work_port)
}

/// 直拨工作端口并完成 NewWorkConn/StartWorkConn 握手，返回就绪的工作连接
async fn dial_and_handshake_bridge_work_conn(
    work_port: u16,
    run_id: &str,
    proxy_name: &str,
    token: &str,
    bridge_id: &str,
    bridge_sign_key: &str,
) -> tokio::net::TcpStream {
    match dial_and_handshake_bridge_work_conn_result(
        work_port,
        run_id,
        proxy_name,
        token,
        bridge_id,
        bridge_sign_key,
    )
    .await
    {
        Ok(conn) => conn,
        Err(error) => panic!("{error}"),
    }
}

async fn dial_and_handshake_bridge_work_conn_result(
    work_port: u16,
    run_id: &str,
    proxy_name: &str,
    token: &str,
    bridge_id: &str,
    bridge_sign_key: &str,
) -> Result<tokio::net::TcpStream, String> {
    let mut work_conn = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(format!("127.0.0.1:{work_port}")),
    )
    .await
    .map_err(|_| "dial work port timeout".to_string())?
    .map_err(|e| format!("dial work port: {e}"))?;
    let auth_manager = AuthManager::new(&AuthConfig {
        method: "token".to_string(),
        token: Some(token.to_string()),
        ..Default::default()
    })
    .expect("auth manager");
    let sign_key = auth_manager
        .generate_work_conn_sign_key(run_id)
        .await
        .map_err(|e| format!("sign key: {e}"))?;
    rust_frp_core::write_message(
        &mut work_conn,
        &Message::NewWorkConn(rust_frp_core::NewWorkConnMsg {
            run_id: run_id.to_string(),
            proxy_name: proxy_name.to_string(),
            timestamp: rust_frp_util::get_timestamp(),
            sign_key,
            bridge_id: bridge_id.to_string(),
            bridge_sign_key: bridge_sign_key.to_string(),
            use_encryption: false,
            use_compression: false,
        }),
    )
    .await
    .map_err(|e| format!("send NewWorkConn: {e}"))?;
    let start = tokio::time::timeout(
        Duration::from_secs(5),
        rust_frp_core::read_message(&mut work_conn),
    )
    .await
    .map_err(|_| "StartWorkConn timeout".to_string())?
    .map_err(|e| format!("read StartWorkConn: {e}"))?;
    match start {
        Message::StartWorkConn(s) => {
            if !s.error.is_empty() {
                return Err(s.error);
            }
        }
        other => return Err(format!("expected StartWorkConn, got {other:?}")),
    }
    Ok(work_conn)
}

/// STCP 桥接全链路：服务端**自定义工作端口**（≠ bind_port+1000）下，
/// 代理侧与访问者侧各自拨该端口，桥接管理器配对后双向中继数据。
///
/// 覆盖：
/// 1. LoginResp 下发自定义工作端口（客户端不得按 server_port+1000 推算）；
/// 2. STCP 注册（secret_key 登记）→ 访问者签名 → 建桥；
/// 3. 桥接路径回发 StartWorkConn（b22ef43 修复：两端不再永久挂起）；
/// 4. 两条腿均拨自定义工作端口且 HMAC 签名照常校验；
/// 5. 数据经桥双向中继。
///
/// 多线程 runtime：与生产环境一致；进程级看门狗防「停更即冻 runtime」。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stcp_bridge_relays_over_custom_work_port() {
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop2 = stop.clone();
    let proc_watchdog = std::thread::spawn(move || {
        for i in 0..60u32 {
            if stop2.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
            eprintln!("[proc-watchdog] alive #{}", i);
        }
    });
    let _guard = server_lock().await;
    let token = "dual-port-secret";
    let work_port = free_tcp_port(); // 自定义工作端口
    let (bind_port, advertised) = start_server_with_work_port(token, work_port).await;

    // 1. 代理侧控制连接：登录 + 注册 STCP 代理（登记 secret_key）
    let (mut ctrl_proxy, resp) = connect_and_login(bind_port, token, "stcp-proxy-run").await;
    assert!(resp.error.is_empty(), "login rejected: {}", resp.error);
    assert_eq!(
        resp.work_conn_port, advertised,
        "LoginResp must advertise the custom work conn port"
    );
    assert_ne!(
        advertised,
        bind_port + 1000,
        "custom work port must differ from the default for this test to be meaningful"
    );
    rust_frp_core::write_message(
        &mut ctrl_proxy,
        &Message::RegisterProxy(rust_frp_core::RegisterProxyMsg {
            proxy: ProxyConfig {
                name: "stcpbridge".to_string(),
                r#type: "stcp".to_string(),
                local_ip: "127.0.0.1".to_string(),
                local_port: 1, // 桥接路径不连本地服务，占位即可
                remote_port: None,
                secret_key: Some("stcp-bridge-secret".to_string()),
                ..Default::default()
            },
        }),
    )
    .await
    .expect("send register proxy");
    match tokio::time::timeout(
        Duration::from_secs(5),
        rust_frp_core::read_message(&mut ctrl_proxy),
    )
    .await
    .expect("register resp within timeout")
    .expect("read register resp")
    {
        Message::RegisterProxyResp(r) => {
            assert!(r.error.is_empty(), "register rejected: {}", r.error)
        }
        other => panic!("expected RegisterProxyResp, got {other:?}"),
    }

    // 2. 访问者侧控制连接：签名后发送 StcpVisitor
    // （独立 client_id：同 client_id 会触发 kick_same_client 踢掉代理侧连接）
    let (mut ctrl_visitor, _) =
        connect_and_login_as(bind_port, token, "stcp-visitor-run", "dual-port-visitor").await;
    let ts = rust_frp_util::get_timestamp();
    let bridge_id = rust_frp_util::rand_id(24);
    let sign_key = rust_frp_auth::generate_stcp_visitor_sign_key(
        "stcp-bridge-secret",
        "stcpbridge",
        &bridge_id,
        "stcp-visitor-run",
        ts,
    );
    rust_frp_core::write_message(
        &mut ctrl_visitor,
        &Message::StcpVisitor(rust_frp_core::StcpVisitorMsg {
            proxy_name: "stcpbridge".to_string(),
            run_id: "stcp-visitor-run".to_string(),
            bridge_id: bridge_id.clone(),
            timestamp: ts,
            sign_key,
        }),
    )
    .await
    .expect("send StcpVisitor");

    // 3. 代理侧收到 ReqWorkConn → 拨自定义工作端口（b22ef43：桥路径回发 StartWorkConn）
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let owner_bridge_sign_key = loop {
        let msg = tokio::time::timeout_at(deadline, rust_frp_core::read_message(&mut ctrl_proxy))
            .await
            .expect("ReqWorkConn within timeout")
            .expect("read control message");
        match msg {
            Message::ReqWorkConn(r) => {
                assert_eq!(r.proxy_name, "stcpbridge");
                assert_eq!(r.bridge_id, bridge_id);
                break r.work_conn_sign_key;
            }
            _ => continue,
        }
    };
    let mut proxy_leg = dial_and_handshake_bridge_work_conn(
        work_port,
        "stcp-proxy-run",
        "stcpbridge",
        token,
        &bridge_id,
        &owner_bridge_sign_key,
    )
    .await;
    eprintln!(
        "[ckpt] proxy leg established on custom work port {}",
        work_port
    );

    // 4. 访问者侧收到桥就绪确认（StcpVisitorResp）→ 拨自定义工作端口
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let visitor_bridge_sign_key = loop {
        let msg = tokio::time::timeout_at(deadline, rust_frp_core::read_message(&mut ctrl_visitor))
            .await
            .expect("StcpVisitorResp within timeout")
            .expect("read control message");
        match msg {
            Message::StcpVisitorResp(r) => {
                assert!(r.error.is_empty(), "StcpVisitorResp error: {}", r.error);
                assert_eq!(r.bridge_id, bridge_id);
                break r.work_conn_sign_key;
            }
            _ => continue,
        }
    };
    let mut visitor_leg = dial_and_handshake_bridge_work_conn(
        work_port,
        "stcp-visitor-run",
        "stcpbridge",
        token,
        &bridge_id,
        &visitor_bridge_sign_key,
    )
    .await;
    eprintln!("[ckpt] visitor leg established, bridge pairing");

    // 5. 桥双向中继：代理侧写 → 访问者侧读；访问者侧写 → 代理侧读
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    proc_watchdog.join().ok();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(Duration::from_secs(5), async {
        proxy_leg
            .write_all(b"proxy-to-visitor")
            .await
            .expect("proxy leg write");
        proxy_leg.flush().await.expect("proxy leg flush");
        let mut buf = [0u8; 16];
        visitor_leg
            .read_exact(&mut buf)
            .await
            .expect("visitor leg read");
        assert_eq!(&buf, b"proxy-to-visitor");

        visitor_leg
            .write_all(b"visitor-to-proxy")
            .await
            .expect("visitor leg write");
        visitor_leg.flush().await.expect("visitor leg flush");
        let mut buf2 = [0u8; 16];
        proxy_leg
            .read_exact(&mut buf2)
            .await
            .expect("proxy leg read");
        assert_eq!(&buf2, b"visitor-to-proxy");
    })
    .await
    .expect("bridge relay within timeout");
    eprintln!("[ckpt] stcp bridge relay verified over custom work port");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stcp_work_conn_requires_bridge_secret() {
    let _guard = server_lock().await;
    let token = "stcp-auth-token";
    let work_port = free_tcp_port();
    let (bind_port, _) = start_server_with_work_port(token, work_port).await;

    let (mut owner_ctrl, _) =
        connect_and_login_as(bind_port, token, "stcp-owner", "stcp-owner").await;
    rust_frp_core::write_message(
        &mut owner_ctrl,
        &Message::RegisterProxy(rust_frp_core::RegisterProxyMsg {
            proxy: ProxyConfig {
                name: "stcp-auth".to_string(),
                r#type: "stcp".to_string(),
                local_ip: "127.0.0.1".to_string(),
                local_port: 1,
                secret_key: Some("real-stcp-secret".to_string()),
                ..Default::default()
            },
        }),
    )
    .await
    .expect("register owner proxy");
    match rust_frp_core::read_message(&mut owner_ctrl)
        .await
        .expect("owner register response")
    {
        Message::RegisterProxyResp(resp) => assert!(resp.error.is_empty(), "{}", resp.error),
        other => panic!("expected RegisterProxyResp, got {other:?}"),
    }

    let (mut visitor_ctrl, _) =
        connect_and_login_as(bind_port, token, "stcp-visitor", "stcp-visitor").await;
    let bridge_id = rust_frp_util::rand_id(24);
    let ts = rust_frp_util::get_timestamp();
    let sign_key = rust_frp_auth::generate_stcp_visitor_sign_key(
        "real-stcp-secret",
        "stcp-auth",
        &bridge_id,
        "stcp-visitor",
        ts,
    );
    rust_frp_core::write_message(
        &mut visitor_ctrl,
        &Message::StcpVisitor(rust_frp_core::StcpVisitorMsg {
            proxy_name: "stcp-auth".to_string(),
            run_id: "stcp-visitor".to_string(),
            bridge_id: bridge_id.clone(),
            timestamp: ts,
            sign_key,
        }),
    )
    .await
    .expect("send visitor request");

    let response = tokio::time::timeout(
        Duration::from_secs(5),
        rust_frp_core::read_message(&mut visitor_ctrl),
    )
    .await
    .expect("visitor response timeout")
    .expect("read visitor response");
    match response {
        Message::StcpVisitorResp(resp) => {
            assert!(resp.error.is_empty(), "{}", resp.error);
            assert_eq!(resp.bridge_id, bridge_id);
        }
        other => panic!("expected StcpVisitorResp, got {other:?}"),
    }

    let (attacker_ctrl, _) =
        connect_and_login_as(bind_port, token, "stcp-attacker", "stcp-attacker").await;
    assert!(
        attacker_ctrl.peer_addr().is_ok(),
        "attacker control must stay online"
    );
    let error = dial_and_handshake_bridge_work_conn_result(
        work_port,
        "stcp-attacker",
        "stcp-auth",
        token,
        &bridge_id,
        "guessed-without-secret",
    )
    .await
    .expect_err("work conn without STCP secret must be rejected");
    assert!(
        error.contains("authorization failed"),
        "unexpected rejection: {error}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_stcp_visitors_use_independent_bridges() {
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _guard = server_lock().await;
    let token = "stcp-concurrent-token";
    let work_port = free_tcp_port();
    let (bind_port, _) = start_server_with_work_port(token, work_port).await;

    let (mut owner_ctrl, _) =
        connect_and_login_as(bind_port, token, "stcp-owner", "stcp-owner").await;
    rust_frp_core::write_message(
        &mut owner_ctrl,
        &Message::RegisterProxy(rust_frp_core::RegisterProxyMsg {
            proxy: ProxyConfig {
                name: "stcp-shared".to_string(),
                r#type: "stcp".to_string(),
                local_ip: "127.0.0.1".to_string(),
                local_port: 1,
                secret_key: Some("shared-secret".to_string()),
                ..Default::default()
            },
        }),
    )
    .await
    .expect("register owner proxy");
    match rust_frp_core::read_message(&mut owner_ctrl)
        .await
        .expect("owner register response")
    {
        Message::RegisterProxyResp(resp) => assert!(resp.error.is_empty(), "{}", resp.error),
        other => panic!("expected RegisterProxyResp, got {other:?}"),
    }

    let (mut visitor1_ctrl, _) = connect_and_login_as(bind_port, token, "stcp-v1", "stcp-v1").await;
    let (mut visitor2_ctrl, _) = connect_and_login_as(bind_port, token, "stcp-v2", "stcp-v2").await;
    let bridge1 = rust_frp_util::rand_id(24);
    let bridge2 = rust_frp_util::rand_id(24);
    for (ctrl, run_id, bridge_id) in [
        (&mut visitor1_ctrl, "stcp-v1", &bridge1),
        (&mut visitor2_ctrl, "stcp-v2", &bridge2),
    ] {
        let ts = rust_frp_util::get_timestamp();
        rust_frp_core::write_message(
            ctrl,
            &Message::StcpVisitor(rust_frp_core::StcpVisitorMsg {
                proxy_name: "stcp-shared".to_string(),
                run_id: run_id.to_string(),
                bridge_id: bridge_id.clone(),
                timestamp: ts,
                sign_key: rust_frp_auth::generate_stcp_visitor_sign_key(
                    "shared-secret",
                    "stcp-shared",
                    bridge_id,
                    run_id,
                    ts,
                ),
            }),
        )
        .await
        .expect("send concurrent visitor request");
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut owner_keys = HashMap::new();
    while owner_keys.len() < 2 {
        match tokio::time::timeout_at(deadline, rust_frp_core::read_message(&mut owner_ctrl))
            .await
            .expect("owner ReqWorkConn timeout")
            .expect("owner control read")
        {
            Message::ReqWorkConn(req) => {
                assert!(req.bridge_id == bridge1 || req.bridge_id == bridge2);
                owner_keys.insert(req.bridge_id, req.work_conn_sign_key);
            }
            _ => continue,
        }
    }

    let mut visitor_keys = HashMap::new();
    for (ctrl, expected_bridge) in [
        (&mut visitor1_ctrl, &bridge1),
        (&mut visitor2_ctrl, &bridge2),
    ] {
        loop {
            match tokio::time::timeout(Duration::from_secs(5), rust_frp_core::read_message(ctrl))
                .await
                .expect("visitor response timeout")
                .expect("visitor control read")
            {
                Message::StcpVisitorResp(resp) => {
                    assert!(resp.error.is_empty(), "{}", resp.error);
                    assert_eq!(&resp.bridge_id, expected_bridge);
                    visitor_keys.insert(resp.bridge_id, resp.work_conn_sign_key);
                    break;
                }
                _ => continue,
            }
        }
    }

    let mut owner1 = dial_and_handshake_bridge_work_conn(
        work_port,
        "stcp-owner",
        "stcp-shared",
        token,
        &bridge1,
        &owner_keys[&bridge1],
    )
    .await;
    let mut owner2 = dial_and_handshake_bridge_work_conn(
        work_port,
        "stcp-owner",
        "stcp-shared",
        token,
        &bridge2,
        &owner_keys[&bridge2],
    )
    .await;
    let mut visitor1 = dial_and_handshake_bridge_work_conn(
        work_port,
        "stcp-v1",
        "stcp-shared",
        token,
        &bridge1,
        &visitor_keys[&bridge1],
    )
    .await;
    let mut visitor2 = dial_and_handshake_bridge_work_conn(
        work_port,
        "stcp-v2",
        "stcp-shared",
        token,
        &bridge2,
        &visitor_keys[&bridge2],
    )
    .await;

    tokio::time::timeout(Duration::from_secs(5), async {
        owner1.write_all(b"owner-one").await.expect("owner1 write");
        owner2.write_all(b"owner-two").await.expect("owner2 write");
        let mut v1 = [0u8; 9];
        let mut v2 = [0u8; 9];
        visitor1.read_exact(&mut v1).await.expect("visitor1 read");
        visitor2.read_exact(&mut v2).await.expect("visitor2 read");
        assert_eq!(&v1, b"owner-one");
        assert_eq!(&v2, b"owner-two");

        visitor1
            .write_all(b"visitor-1")
            .await
            .expect("visitor1 write");
        visitor2
            .write_all(b"visitor-2")
            .await
            .expect("visitor2 write");
        let mut o1 = [0u8; 9];
        let mut o2 = [0u8; 9];
        owner1.read_exact(&mut o1).await.expect("owner1 read");
        owner2.read_exact(&mut o2).await.expect("owner2 read");
        assert_eq!(&o1, b"visitor-1");
        assert_eq!(&o2, b"visitor-2");
    })
    .await
    .expect("concurrent STCP bridges timed out");
}

#[tokio::test]
async fn login_resp_advertises_work_conn_port() {
    let _guard = server_lock().await;
    let token = "dual-port-secret";
    let bind_port = start_server(token).await;
    let (_conn, resp) = connect_and_login(bind_port, token, "dual-port-advertise").await;
    assert!(resp.error.is_empty(), "login rejected: {}", resp.error);
    assert_eq!(
        resp.work_conn_port,
        bind_port + 1000,
        "LoginResp must advertise the real work conn port"
    );
}

/// 完整数据面链路：访问者 → frps → 工作端口 → 本地 echo → 回程
///
/// 多线程 runtime：服务端任务与测试体并发执行，与生产环境（多线程 tokio）一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_proxy_data_flows_over_dedicated_work_port() {
    // 进程级看门狗（独立 OS 线程，不受 tokio 影响）：
    // 停更 = 整个进程被阻塞（OS 级）；仍在跳 = tokio runtime 被同步代码饿死
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop2 = stop.clone();
    let proc_watchdog = std::thread::spawn(move || {
        for i in 0..60u32 {
            if stop2.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
            eprintln!("[proc-watchdog] alive #{}", i);
        }
    });
    let _guard = server_lock().await;
    let token = "dual-port-secret";
    let bind_port = start_server(token).await;
    let work_port = bind_port + 1000;

    // 1. 控制连接登录 + 断言服务端下发工作端口
    let (mut control, login_resp) = connect_and_login(bind_port, token, "dual-port-run").await;
    assert_eq!(login_resp.work_conn_port, work_port);

    // 2. 注册 TCP 代理（remote_port → 本地 echo）
    eprintln!("[ckpt] login ok, registering proxy");
    let echo_port = start_echo_server().await;
    let remote_port = free_tcp_port();
    rust_frp_core::write_message(
        &mut control,
        &Message::RegisterProxy(rust_frp_core::RegisterProxyMsg {
            proxy: ProxyConfig {
                name: "dualport".to_string(),
                r#type: "tcp".to_string(),
                local_ip: "127.0.0.1".to_string(),
                local_port: echo_port,
                remote_port: Some(remote_port),
                ..Default::default()
            },
        }),
    )
    .await
    .expect("send register proxy");
    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        rust_frp_core::read_message(&mut control),
    )
    .await
    .expect("register proxy resp within timeout")
    .expect("read register proxy resp");
    match resp {
        Message::RegisterProxyResp(r) => {
            assert!(r.error.is_empty(), "register proxy rejected: {}", r.error);
        }
        other => panic!("expected RegisterProxyResp, got {other:?}"),
    }

    // 3. 访问者连上 remote_port → 服务端从控制连接发 ReqWorkConn
    eprintln!("[ckpt] register ok, visitor connecting to {}", remote_port);
    let mut visitor = tokio::net::TcpStream::connect(format!("127.0.0.1:{remote_port}"))
        .await
        .expect("visitor connect");
    eprintln!("[ckpt] visitor connected, waiting ReqWorkConn");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let msg = tokio::time::timeout_at(deadline, rust_frp_core::read_message(&mut control))
            .await
            .expect("ReqWorkConn within timeout")
            .expect("read control message");
        match msg {
            Message::ReqWorkConn(r) => {
                assert_eq!(r.proxy_name, "dualport");
                break;
            }
            // 服务端可能夹杂其他控制消息（如池预热的 ReqWorkConn），跳过
            _ => continue,
        }
    }

    // 4. 直拨专用工作端口，完成 NewWorkConn/StartWorkConn 握手
    eprintln!(
        "[ckpt] ReqWorkConn received, dialing work port {}",
        work_port
    );
    // 心跳看门狗：每 2s 打一条，若停更说明 runtime 被同步代码阻塞
    let watchdog = tokio::spawn(async {
        for i in 0..30u32 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            eprintln!("[watchdog] alive #{}", i);
        }
    });
    let work_addr = format!("127.0.0.1:{work_port}");
    let mut work_conn = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(&work_addr),
    )
    .await
    .expect("dial dedicated work port within timeout")
    .expect("dial dedicated work port");
    eprintln!("[ckpt] work port connected");
    let auth_manager = AuthManager::new(&AuthConfig {
        method: "token".to_string(),
        token: Some(token.to_string()),
        ..Default::default()
    })
    .expect("auth manager");
    let sign_key = tokio::time::timeout(
        Duration::from_secs(2),
        auth_manager.generate_work_conn_sign_key("dual-port-run"),
    )
    .await
    .expect("sign key within timeout")
    .expect("sign key");
    eprintln!("[ckpt] sign key ready, sending NewWorkConn");
    tokio::time::timeout(
        Duration::from_secs(5),
        rust_frp_core::write_message(
            &mut work_conn,
            &Message::NewWorkConn(rust_frp_core::NewWorkConnMsg {
                run_id: "dual-port-run".to_string(),
                proxy_name: "dualport".to_string(),
                timestamp: rust_frp_util::get_timestamp(),
                sign_key,
                use_encryption: false,
                use_compression: false,
                ..Default::default()
            }),
        ),
    )
    .await
    .expect("send NewWorkConn within timeout")
    .expect("send NewWorkConn");
    eprintln!("[ckpt] NewWorkConn sent, waiting StartWorkConn");
    let start = tokio::time::timeout(
        Duration::from_secs(5),
        rust_frp_core::read_message(&mut work_conn),
    )
    .await
    .expect("StartWorkConn within timeout")
    .expect("read StartWorkConn");
    match start {
        Message::StartWorkConn(s) => {
            assert!(s.error.is_empty(), "StartWorkConn error: {}", s.error);
        }
        other => panic!("expected StartWorkConn, got {other:?}"),
    }
    eprintln!("[ckpt] StartWorkConn ok, bridging to local echo");

    // 5. 模拟客户端本地桥接：工作连接 ↔ 本地 echo 服务
    let mut echo_conn = tokio::net::TcpStream::connect(format!("127.0.0.1:{echo_port}"))
        .await
        .expect("connect local echo");
    let _bridge = tokio::spawn(async move {
        let _ = tokio::io::copy_bidirectional(&mut work_conn, &mut echo_conn).await;
    });

    // 6. 访问者数据经整条链路回环
    eprintln!("[ckpt] bridge spawned, sending visitor payload");
    watchdog.abort();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    proc_watchdog.join().ok();
    tokio::time::timeout(Duration::from_secs(5), async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        visitor
            .write_all(b"hello-dual-port")
            .await
            .expect("visitor write");
        visitor.flush().await.expect("visitor flush");
        let mut buf = [0u8; 15];
        visitor
            .read_exact(&mut buf)
            .await
            .expect("visitor read echo");
        assert_eq!(&buf, b"hello-dual-port");
    })
    .await
    .expect("data roundtrip within timeout");
    eprintln!("[ckpt] roundtrip ok — dual-port data plane verified");
}
