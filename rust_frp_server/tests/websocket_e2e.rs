//! WebSocket 传输端到端测试（`websocket` 明文 / `wss` TLS 叠加）
//!
//! 覆盖重点（本次新增的风险点）：
//! 1. 服务端在控制端口上按首字节嗅探 `GET ` 前缀，识别**明文 WebSocket** 控制连接
//!    并完成 HTTP Upgrade；
//! 2. `wss` 场景：服务端先完成 TLS 握手，再在解密流上识别 `GET ` 前缀并升级为
//!    WebSocket（前缀字节经 `PrefixedStream` 回放，握手不丢包）；
//! 3. 升级后的连接可直接承载 frp 控制协议（登录 → `LoginResp`）；
//! 4. `wss` 下服务端协商工作连接 TLS（`work_conn_tls = true`）。

use rust_frp_config::{AuthConfig, ServerConfig, TlsConfig, TransportConfig};
use rust_frp_core::{LoginMsg, Message};
use rust_frp_net::{
    client_websocket_stream, AnyConn, TlsConfig as NetTlsConfig, WebSocketConn, FRP_WS_PATH,
};
use std::net::SocketAddr;
use std::time::Duration;

/// 申请一个当前空闲的 TCP 端口（bind :0 后立即释放）
fn free_tcp_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind tcp :0");
    l.local_addr().expect("local addr").port()
}

/// 启动一个 frps（TLS 可选），返回 (控制端口, token)
async fn start_server(tls_enable: bool, token: &str) -> u16 {
    let bind_port = free_tcp_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".to_string(),
        bind_port,
        work_conn_port: Some(bind_port + 1000),
        vhost_http_port: Some(free_tcp_port()),
        vhost_https_port: Some(free_tcp_port()),
        auth: AuthConfig {
            method: "token".to_string(),
            token: Some(token.to_string()),
            ..Default::default()
        },
        transport: TransportConfig {
            tls: Some(TlsConfig {
                enable: tls_enable,
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
    bind_port
}

fn login_msg(token: &str, run_id: &str) -> LoginMsg {
    LoginMsg {
        arch: "x86_64".to_string(),
        os: "linux".to_string(),
        hostname: "ws-e2e".to_string(),
        pool_count: 1,
        user: String::new(),
        client_id: "ws-e2e-client".to_string(),
        version: "0.1.0".to_string(),
        timestamp: rust_frp_util::get_timestamp(),
        run_id: run_id.to_string(),
        token: token.to_string(),
        metas: std::collections::HashMap::new(),
        client_spec: None,
    }
}

/// 带重试地建立明文 WebSocket 控制连接（等待监听器就绪）
async fn connect_ws(port: u16) -> WebSocketConn<AnyConn> {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    let url = format!("ws://127.0.0.1:{port}{FRP_WS_PATH}");
    for _ in 0..20 {
        if let Ok(tcp) = tokio::net::TcpStream::connect(addr).await {
            let stream = Box::new(tcp) as AnyConn;
            if let Ok(ws) = client_websocket_stream(stream, &url, addr).await {
                return ws;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("websocket connect to 127.0.0.1:{port} failed after retries");
}

/// 带重试地建立 wss 控制连接（TCP → TLS → WebSocket）
async fn connect_wss(port: u16) -> WebSocketConn<AnyConn> {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    let url = format!("wss://127.0.0.1:{port}{FRP_WS_PATH}");
    for _ in 0..20 {
        if let Ok(tcp) = tokio::net::TcpStream::connect(addr).await {
            let tls = match NetTlsConfig::new_client_insecure() {
                Ok(t) => t,
                Err(e) => panic!("client tls config: {e}"),
            };
            if let Ok(tls_stream) = tls.connect("localhost", tcp).await {
                let stream = Box::new(tls_stream) as AnyConn;
                if let Ok(ws) = client_websocket_stream(stream, &url, addr).await {
                    return ws;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("wss connect to 127.0.0.1:{port} failed after retries");
}

/// 在指定连接上完成登录并返回 `LoginResp`
async fn login(
    conn: &mut WebSocketConn<AnyConn>,
    token: &str,
    run_id: &str,
) -> rust_frp_core::LoginRespMsg {
    rust_frp_core::write_message(conn, &Message::Login(login_msg(token, run_id)))
        .await
        .expect("send login");
    let resp = tokio::time::timeout(Duration::from_secs(5), rust_frp_core::read_message(conn))
        .await
        .expect("login resp within timeout")
        .expect("read login resp");
    match resp {
        Message::LoginResp(r) => r,
        other => panic!("expected LoginResp, got {other:?}"),
    }
}

#[tokio::test]
async fn plain_websocket_control_login_completes() {
    let token = "ws-secret";
    let port = start_server(false, token).await;
    let mut ws = connect_ws(port).await;

    let resp = login(&mut ws, token, "ws-run-id").await;
    assert!(resp.error.is_empty(), "login rejected: {}", resp.error);
    // 服务端未启用 TLS → 不协商工作连接 TLS
    assert!(!resp.work_conn_tls);
}

#[tokio::test]
async fn wss_control_login_completes_over_tls_websocket() {
    let token = "ws-secret";
    let port = start_server(true, token).await;
    let mut ws = connect_wss(port).await;

    let resp = login(&mut ws, token, "wss-run-id").await;
    assert!(resp.error.is_empty(), "login rejected: {}", resp.error);
    // 服务端启用 TLS → 协商工作连接 TLS
    assert!(resp.work_conn_tls);
}

#[tokio::test]
async fn wss_rejects_wrong_token() {
    let port = start_server(true, "ws-secret").await;
    let mut ws = connect_wss(port).await;

    rust_frp_core::write_message(
        &mut ws,
        &Message::Login(login_msg("wrong-token", "wss-bad")),
    )
    .await
    .expect("send login");

    // 认证失败时服务端**回一条带原因的 LoginResp** 再关闭连接 —— 与原版 frp 一致。
    // 这样一来客户端能打印 "login verification failed: invalid credentials"，
    // 而不是只看到 "Login failed: early eof" 把配置错误误判成网络抖动（可诊断性）。
    let msg = tokio::time::timeout(Duration::from_secs(5), rust_frp_core::read_message(&mut ws))
        .await
        .expect("read within timeout")
        .expect("auth failure must answer with a LoginResp carrying the reason");
    match msg {
        Message::LoginResp(resp) => {
            assert!(!resp.error.is_empty(), "auth failure must carry a reason");
            assert!(
                resp.run_id.is_empty(),
                "a failed login must not hand out a run_id, got {:?}",
                resp.run_id
            );
            // 错误文本不得回显客户端送来的令牌（防日志泄露）
            assert!(
                !resp.error.contains("wrong-token"),
                "error text must not echo the token: {}",
                resp.error
            );
        }
        other => panic!("expected LoginResp on auth failure, got {other:?}"),
    }

    // 回完错误响应后连接应立即关闭（读取以错误/EOF 结束）
    let after = tokio::time::timeout(Duration::from_secs(5), rust_frp_core::read_message(&mut ws))
        .await
        .expect("read within timeout");
    assert!(
        after.is_err(),
        "connection should be closed after the auth-failure response, got {after:?}"
    );
}
