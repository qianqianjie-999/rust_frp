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

fn login_msg(token: &str, run_id: &str) -> LoginMsg {
    LoginMsg {
        arch: "x86_64".to_string(),
        os: "linux".to_string(),
        hostname: "dual-port-e2e".to_string(),
        pool_count: 1,
        user: String::new(),
        client_id: "dual-port-client".to_string(),
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
) -> (
    tokio::net::TcpStream,
    rust_frp_core::LoginRespMsg,
) {
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

    rust_frp_core::write_message(&mut conn, &Message::Login(login_msg(token, run_id)))
        .await
        .expect("send login");
    let resp = tokio::time::timeout(Duration::from_secs(5), rust_frp_core::read_message(&mut conn))
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
    eprintln!("[ckpt] ReqWorkConn received, dialing work port {}", work_port);
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
