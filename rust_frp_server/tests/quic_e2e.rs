//! QUIC 传输端到端测试：真实起一个 frps（仅 QUIC 监听），用 rust_frp_net 的
//! QUIC 客户端走完「连接 → 双向流 → 首消息分派 → 登录应答」全链路。
//!
//! 覆盖重点（QUIC 新增的风险点）：
//! 1. 服务端在 `quic_bind_port` 上起 QUIC endpoint 并接受双向流；
//! 2. 服务端按流上**首条消息**把 `Login` 与 `NewWorkConn` 分派到不同处理路径；
//! 3. `Login` 分派复用已读消息（`pre_read_login`）后仍能正常完成鉴权并回 `LoginResp`；
//! 4. `NewWorkConn` 分派确实走工作连接路径（以未知 run_id 得到 `StartWorkConn` 错误为证）。

use rust_frp_config::{AuthConfig, ServerConfig, TlsConfig, TransportConfig};
use rust_frp_core::{LoginMsg, Message, NewWorkConnMsg};
use rust_frp_net::{build_quic_client_config, QuicOptions, QuicSession};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// 申请一个当前空闲的 TCP 端口（bind :0 后立即释放）
fn free_tcp_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind tcp :0");
    l.local_addr().expect("local addr").port()
}

/// 申请一个当前空闲的 UDP 端口（bind :0 后立即释放）
fn free_udp_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp :0");
    s.local_addr().expect("local addr").port()
}

struct QuicServer {
    quic_port: u16,
    token: String,
}

/// 启动一个只开 QUIC 的 frps（其余监听器占用空闲端口，避免与 9090/9091 冲突）
async fn start_quic_server(token: &str) -> QuicServer {
    let bind_port = free_tcp_port();
    let quic_port = free_udp_port();

    // 注意：web_server.port / vhost 端口均在下方显式指定或取 Default(0 = 禁用)
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".to_string(),
        bind_port,
        work_conn_port: Some(bind_port + 1000),
        quic_bind_port: Some(quic_port),
        vhost_http_port: Some(free_tcp_port()),
        vhost_https_port: Some(free_tcp_port()),
        auth: AuthConfig {
            method: "token".to_string(),
            token: Some(token.to_string()),
            ..Default::default()
        },
        // QUIC 自带 TLS 1.3；此处关闭额外 TLS，避免工作连接协商分支干扰
        transport: TransportConfig {
            tls: Some(TlsConfig {
                enable: false,
                ..Default::default()
            }),
            ..Default::default()
        },
        ..Default::default()
    };

    let mut server = rust_frp_server::Server::new(cfg, None)
        .await
        .expect("server construct");
    tokio::spawn(async move {
        let _ = server.start().await;
    });

    QuicServer {
        quic_port,
        token: token.to_string(),
    }
}

/// 连接 QUIC 控制面（带重试，等待监听器就绪）
async fn connect_quic(port: u16) -> QuicSession {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    let opts = QuicOptions::default();
    let client_cfg = build_quic_client_config(None, true, None, &opts).expect("client quic config");
    for _ in 0..20 {
        if let Ok(s) = QuicSession::connect(addr, "localhost", client_cfg.clone()).await {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("QUIC connect to 127.0.0.1:{port} failed after retries");
}

fn login_msg(token: &str, run_id: &str) -> LoginMsg {
    LoginMsg {
        arch: "x86_64".to_string(),
        os: "linux".to_string(),
        hostname: "quic-e2e".to_string(),
        pool_count: 1,
        user: String::new(),
        client_id: "quic-e2e-client".to_string(),
        version: "0.1.0".to_string(),
        timestamp: rust_frp_util::get_timestamp(),
        run_id: run_id.to_string(),
        token: token.to_string(),
        metas: std::collections::HashMap::new(),
        client_spec: None,
    }
}

#[tokio::test]
async fn quic_control_login_completes_over_stream() {
    let srv = start_quic_server("quic-secret").await;
    let session = connect_quic(srv.quic_port).await;

    // 控制连接 = 首条双向流；首条消息为 Login → 服务端应分派到控制路径
    let mut conn = session.open_stream().await.expect("open control stream");
    rust_frp_core::write_message(
        &mut conn,
        &Message::Login(login_msg(&srv.token, "quic-run-id")),
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
        Message::LoginResp(r) => {
            assert!(r.error.is_empty(), "login rejected: {}", r.error);
            // QUIC 路径不协商额外的工作连接 TLS（工作连接复用同一 QUIC 连接的新流）
            assert!(!r.work_conn_tls);
        }
        other => panic!("expected LoginResp, got {:?}", other),
    }
}

#[tokio::test]
async fn quic_new_work_conn_is_dispatched_to_work_conn_path() {
    let srv = start_quic_server("quic-secret").await;
    let session = connect_quic(srv.quic_port).await;

    // 同一 QUIC 连接上的第二条流，首条消息为 NewWorkConn → 应分派到工作连接路径。
    // 用未知 run_id，服务端必然回 StartWorkConn{error}，以此证明分派正确（而非误入控制路径）。
    let mut conn = session.open_stream().await.expect("open work stream");
    let msg = Message::NewWorkConn(NewWorkConnMsg {
        run_id: "no-such-run-id".to_string(),
        proxy_name: "quic-tcp".to_string(),
        timestamp: rust_frp_util::get_timestamp(),
        sign_key: String::new(),
        use_encryption: false,
        use_compression: false,
    });
    rust_frp_core::write_message(&mut conn, &msg)
        .await
        .expect("send new work conn");

    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        rust_frp_core::read_message(&mut conn),
    )
    .await
    .expect("work conn resp within timeout")
    .expect("read work conn resp");

    match resp {
        Message::StartWorkConn(r) => {
            assert!(
                r.error.contains("Unknown run_id"),
                "expected unknown run_id error, got: {}",
                r.error
            );
        }
        other => panic!("expected StartWorkConn, got {:?}", other),
    }

    // 关闭流，避免任务悬挂
    let _ = conn.shutdown().await;
}
