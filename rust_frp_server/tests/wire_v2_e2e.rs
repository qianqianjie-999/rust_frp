//! wire protocol v2 端到端测试
//!
//! 覆盖重点：
//! 1. v2 客户端（`FRP\x00\x02\r\n` 魔数 + ClientHello/ServerHello 能力协商）在纯 TCP
//!    控制端口上完成登录，且登录/响应均经方向性 AEAD 通道传输；
//! 2. 登录后控制循环（Ping → Pong）在 v2 帧 + AEAD 通道上正常往返；
//! 3. v2 下错误 token 仍被拒绝（认证语义不因新线协议而旁路）；
//! 4. **回归守卫**：不带魔数的 v1 客户端在同一个服务端上仍可正常登录
//!    （服务端嗅探非魔数时必须原样回放嗅探字节）。

use rust_frp_config::{AuthConfig, ServerConfig, TransportConfig};
use rust_frp_core::{LoginMsg, LoginRespMsg, Message};
use rust_frp_net::{AnyConn, BootstrapInfo};
use std::net::SocketAddr;
use std::time::Duration;

/// 申请一个当前空闲的 TCP 端口（bind :0 后立即释放）
///
/// 同时保证 `port + 1000` 不会溢出 u16（`work_conn_port` 需要）。
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

/// 串行化测试用服务端启动：`free_tcp_port` 释放端口到服务端真正 bind 之间存在
/// 窗口，并发启动会互相抢端口。同一测试二进制内串行即可消除该竞争。
static SERVER_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

async fn server_lock() -> tokio::sync::MutexGuard<'static, ()> {
    SERVER_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

/// 启动一个 frps（纯 TCP，token 认证），返回控制端口
async fn start_server(token: &str) -> u16 {
    let bind_port = free_tcp_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".to_string(),
        bind_port,
        work_conn_port: Some(bind_port + 1000),
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
        hostname: "wire-v2-e2e".to_string(),
        pool_count: 1,
        user: String::new(),
        client_id: "wire-v2-client".to_string(),
        version: "0.1.0".to_string(),
        timestamp: rust_frp_util::get_timestamp(),
        run_id: run_id.to_string(),
        token: token.to_string(),
        metas: std::collections::HashMap::new(),
        client_spec: None,
    }
}

/// 带重试地建立 TCP 连接并完成 v2 握手，返回 AEAD 包装后的控制连接
async fn connect_v2(port: u16, token: &str) -> AnyConn {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    let base_key = {
        use ring::digest;
        let mut h = digest::Context::new(&digest::SHA256);
        h.update(token.as_bytes());
        h.finish().as_ref().to_vec()
    };
    for _ in 0..20 {
        if let Ok(tcp) = tokio::net::TcpStream::connect(addr).await {
            let stream = Box::new(tcp) as AnyConn;
            if let Ok(enc) = rust_frp_net::wire_v2::client_handshake(
                stream,
                &base_key,
                BootstrapInfo {
                    transport: "tcp".to_string(),
                    tls: false,
                    tcp_mux: false,
                },
            )
            .await
            {
                return Box::new(enc);
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("wire v2 connect to 127.0.0.1:{port} failed after retries");
}

/// 在 v2 加密通道上完成登录
async fn login_v2<T>(conn: &mut T, token: &str, run_id: &str) -> LoginRespMsg
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    rust_frp_core::write_v2_message(conn, &Message::Login(login_msg(token, run_id)))
        .await
        .expect("send v2 login");
    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        rust_frp_core::read_v2_message(conn, rust_frp_core::MAX_PREAUTH_MESSAGE_SIZE),
    )
    .await
    .expect("login resp within timeout")
    .expect("read v2 login resp");
    match resp {
        Message::LoginResp(r) => r,
        other => panic!("expected LoginResp, got {other:?}"),
    }
}

#[tokio::test]
async fn wire_v2_control_login_completes() {
    let _guard = server_lock().await;
    let token = "wire-v2-secret";
    let port = start_server(token).await;
    let mut conn = connect_v2(port, token).await;

    let resp = login_v2(&mut conn, token, "wire-v2-run-id").await;
    assert!(resp.error.is_empty(), "login rejected: {}", resp.error);
    assert_eq!(resp.run_id, "wire-v2-run-id");
}

#[tokio::test]
async fn wire_v2_ping_pong_over_encrypted_channel() {
    let _guard = server_lock().await;
    let token = "wire-v2-secret";
    let port = start_server(token).await;
    let mut conn = connect_v2(port, token).await;
    let _ = login_v2(&mut conn, token, "wire-v2-ping").await;

    // 心跳在 v2 帧 + AEAD 通道上往返
    rust_frp_core::write_v2_message(
        &mut conn,
        &Message::Ping(rust_frp_core::PingMsg {
            timestamp: rust_frp_util::get_timestamp(),
            privilege_key: String::new(),
        }),
    )
    .await
    .expect("send ping");

    let reply = tokio::time::timeout(
        Duration::from_secs(5),
        rust_frp_core::read_v2_message(&mut conn, rust_frp_core::MAX_PREAUTH_MESSAGE_SIZE),
    )
    .await
    .expect("pong within timeout")
    .expect("read pong");
    assert!(
        matches!(reply, Message::Pong(_)),
        "expected Pong, got {reply:?}"
    );
}

#[tokio::test]
async fn wire_v2_rejects_wrong_token() {
    let _guard = server_lock().await;
    let port = start_server("wire-v2-secret").await;
    // 客户端用错误 token 派生基础密钥：AEAD 层即不匹配，服务端解密失败并断开
    let mut conn = connect_v2(port, "wrong-token").await;

    let _ = rust_frp_core::write_v2_message(
        &mut conn,
        &Message::Login(login_msg("wrong-token", "wire-v2-bad")),
    )
    .await;

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        rust_frp_core::read_v2_message(&mut conn, rust_frp_core::MAX_PREAUTH_MESSAGE_SIZE),
    )
    .await
    .expect("read within timeout");
    assert!(
        result.is_err(),
        "wrong base key must not yield a valid LoginResp, got {result:?}"
    );
}

/// 回归守卫：v1（无魔数）客户端在启用了 v2 嗅探的服务端上仍可登录
#[tokio::test]
async fn v1_client_still_logs_in_after_v2_sniffing() {
    let _guard = server_lock().await;
    let token = "wire-v1-secret";
    let port = start_server(token).await;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");

    let mut conn = None;
    for _ in 0..20 {
        if let Ok(tcp) = tokio::net::TcpStream::connect(addr).await {
            conn = Some(tcp);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut conn = conn.expect("tcp connect");

    // v1 帧：4 字节长度 + JSON（服务端嗅探到的 8 字节必须原样回放）
    rust_frp_core::write_message(&mut conn, &Message::Login(login_msg(token, "v1-run-id")))
        .await
        .expect("send v1 login");
    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        rust_frp_core::read_message(&mut conn),
    )
    .await
    .expect("v1 login resp within timeout")
    .expect("read v1 login resp");
    match resp {
        Message::LoginResp(r) => assert!(r.error.is_empty(), "login rejected: {}", r.error),
        other => panic!("expected LoginResp, got {other:?}"),
    }
}

/// 服务端配置里的 `wire_protocol` 仅作声明；默认 v1 下 v2 客户端仍可协商成功
/// （服务端按魔数嗅探，不依赖该配置项）。此测试同时确认 TransportConfig 新字段
/// 不会破坏默认配置构造。
#[tokio::test]
async fn transport_config_defaults_to_v1_wire_protocol() {
    let cfg = TransportConfig::default();
    assert_eq!(cfg.wire_protocol, "v1");
}
