//! 优雅关闭入口测试：shutdown 后所有 ingress 监听器都必须停止接收新连接。

use rust_frp_config::{AuthConfig, ProxyConfig, ServerConfig};
use rust_frp_core::{LoginMsg, Message};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

fn used_ports() -> &'static Mutex<std::collections::HashSet<u16>> {
    static USED: OnceLock<Mutex<std::collections::HashSet<u16>>> = OnceLock::new();
    USED.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

fn reserve_unique_port(bind: impl Fn() -> u16) -> u16 {
    let mut used = used_ports()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    loop {
        let port = bind();
        if used.insert(port) {
            return port;
        }
    }
}

fn free_tcp_port() -> u16 {
    reserve_unique_port(|| {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind free port");
        listener.local_addr().expect("local addr").port()
    })
}

fn free_udp_port() -> u16 {
    reserve_unique_port(|| {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind free UDP port");
        socket.local_addr().expect("local UDP addr").port()
    })
}

fn login_msg(token: &str) -> LoginMsg {
    LoginMsg {
        arch: std::env::consts::ARCH.to_string(),
        os: std::env::consts::OS.to_string(),
        hostname: "shutdown-ingress".to_string(),
        pool_count: 1,
        user: String::new(),
        client_id: "shutdown-ingress-client".to_string(),
        version: "0.1.0".to_string(),
        timestamp: rust_frp_util::get_timestamp(),
        run_id: "shutdown-ingress-run".to_string(),
        token: token.to_string(),
        metas: std::collections::HashMap::new(),
        client_spec: None,
    }
}

async fn assert_refused(port: u16, label: &str) {
    let result = tokio::time::timeout(
        Duration::from_millis(500),
        tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")),
    )
    .await
    .unwrap_or_else(|_| panic!("{label} connect must not hang after shutdown"));
    assert!(result.is_err(), "{label} still accepts after shutdown");
}

async fn assert_udp_released(port: u16, label: &str) {
    for _ in 0..50 {
        match tokio::net::UdpSocket::bind(format!("127.0.0.1:{port}")).await {
            Ok(socket) => {
                drop(socket);
                return;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    panic!("{label} UDP socket was not released after shutdown");
}

async fn register_proxy(control: &mut tokio::net::TcpStream, proxy: ProxyConfig) {
    rust_frp_core::write_message(
        control,
        &Message::RegisterProxy(rust_frp_core::RegisterProxyMsg { proxy }),
    )
    .await
    .expect("send register proxy");
    let register =
        tokio::time::timeout(Duration::from_secs(2), rust_frp_core::read_message(control))
            .await
            .expect("register response timeout")
            .expect("read register response");
    match register {
        Message::RegisterProxyResp(resp) => assert!(resp.error.is_empty(), "{}", resp.error),
        other => panic!("expected RegisterProxyResp, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_stops_all_ingress_listeners() {
    let token = "shutdown-ingress-token";
    let bind_port = free_tcp_port();
    let work_port = free_tcp_port();
    let tcp_proxy_port = free_tcp_port();
    let ws_proxy_port = free_tcp_port();
    let udp_proxy_port = free_udp_port();
    let vhost_http_port = free_tcp_port();
    let tcpmux_port = free_tcp_port();
    let web_port = free_tcp_port();
    let kcp_port = free_udp_port();
    let quic_port = free_udp_port();

    let config = ServerConfig {
        bind_addr: "127.0.0.1".to_string(),
        bind_port,
        work_conn_port: Some(work_port),
        vhost_http_port: Some(vhost_http_port),
        tcpmux_http_connect_port: Some(tcpmux_port),
        kcp_bind_port: Some(kcp_port),
        quic_bind_port: Some(quic_port),
        web_server: rust_frp_config::WebServerConfig {
            addr: "127.0.0.1".to_string(),
            port: web_port,
            user: Some("admin".to_string()),
            password: Some("shutdown-check".to_string()),
            ..Default::default()
        },
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

    let mut server = rust_frp_server::Server::new(config, None)
        .await
        .expect("server construct");
    let shutdown = server.shutdown_handle();
    let mut server_task = tokio::spawn(async move {
        server.start().await.expect("server start should succeed");
    });

    let mut control = None;
    for _ in 0..50 {
        if let Ok(conn) = tokio::net::TcpStream::connect(format!("127.0.0.1:{bind_port}")).await {
            control = Some(conn);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut control = control.expect("control listener ready");

    rust_frp_core::write_message(&mut control, &Message::Login(login_msg(token)))
        .await
        .expect("send login");
    let login = tokio::time::timeout(
        Duration::from_secs(2),
        rust_frp_core::read_message(&mut control),
    )
    .await
    .expect("login response timeout")
    .expect("read login response");
    assert!(matches!(login, Message::LoginResp(_)));

    register_proxy(
        &mut control,
        ProxyConfig {
            name: "shutdown-tcp".to_string(),
            r#type: "tcp".to_string(),
            local_ip: "127.0.0.1".to_string(),
            local_port: 9,
            remote_port: Some(tcp_proxy_port),
            ..Default::default()
        },
    )
    .await;
    register_proxy(
        &mut control,
        ProxyConfig {
            name: "shutdown-ws".to_string(),
            r#type: "websocket".to_string(),
            local_ip: "127.0.0.1".to_string(),
            local_port: 9,
            remote_port: Some(ws_proxy_port),
            ..Default::default()
        },
    )
    .await;
    register_proxy(
        &mut control,
        ProxyConfig {
            name: "shutdown-udp".to_string(),
            r#type: "udp".to_string(),
            local_ip: "127.0.0.1".to_string(),
            local_port: 9,
            remote_port: Some(udp_proxy_port),
            ..Default::default()
        },
    )
    .await;

    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(format!("127.0.0.1:{tcp_proxy_port}")),
    )
    .await
    .expect("proxy listener should start")
    .expect("proxy listener accepts before shutdown");
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(format!("127.0.0.1:{ws_proxy_port}")),
    )
    .await
    .expect("WebSocket proxy listener should start")
    .expect("WebSocket proxy listener accepts before shutdown");
    assert!(
        tokio::net::UdpSocket::bind(format!("127.0.0.1:{udp_proxy_port}"))
            .await
            .is_err(),
        "UDP proxy listener should be bound before shutdown"
    );
    assert!(
        tokio::net::UdpSocket::bind(format!("127.0.0.1:{kcp_port}"))
            .await
            .is_err(),
        "KCP listener should be bound before shutdown"
    );
    assert!(
        tokio::net::UdpSocket::bind(format!("127.0.0.1:{quic_port}"))
            .await
            .is_err(),
        "QUIC listener should be bound before shutdown"
    );

    shutdown.notify_waiters();
    shutdown.notify_one();
    tokio::time::timeout(Duration::from_secs(2), &mut server_task)
        .await
        .expect("server accept loops should stop")
        .expect("server task join");

    assert_refused(bind_port, "control listener").await;
    assert_refused(tcp_proxy_port, "TCP proxy listener").await;
    assert_refused(ws_proxy_port, "WebSocket proxy listener").await;
    assert_refused(vhost_http_port, "HTTP vhost listener").await;
    assert_refused(tcpmux_port, "tcpmux listener").await;
    assert_refused(web_port, "dashboard listener").await;
    assert_refused(work_port, "work connection listener").await;
    assert_udp_released(udp_proxy_port, "UDP proxy").await;
    assert_udp_released(kcp_port, "KCP").await;
    assert_udp_released(quic_port, "QUIC").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_stops_tls_vhost_listener() {
    let token = "shutdown-tls-token";
    let bind_port = free_tcp_port();
    let work_port = free_tcp_port();
    let vhost_http_port = free_tcp_port();
    let vhost_https_port = free_tcp_port();

    let config = ServerConfig {
        bind_addr: "127.0.0.1".to_string(),
        bind_port,
        work_conn_port: Some(work_port),
        vhost_http_port: Some(vhost_http_port),
        vhost_https_port: Some(vhost_https_port),
        transport: rust_frp_config::TransportConfig {
            tls: Some(rust_frp_config::TlsConfig {
                enable: true,
                ..Default::default()
            }),
            ..Default::default()
        },
        auth: AuthConfig {
            method: "token".to_string(),
            token: Some(token.to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

    let mut server = rust_frp_server::Server::new(config, None)
        .await
        .expect("server construct");
    let shutdown = server.shutdown_handle();
    let mut server_task = tokio::spawn(async move {
        server.start().await.expect("server start should succeed");
    });

    let mut control = None;
    for _ in 0..50 {
        if let Ok(conn) = tokio::net::TcpStream::connect(format!("127.0.0.1:{bind_port}")).await {
            control = Some(conn);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let tcp = control.expect("control listener ready");
    let client_tls = rust_frp_net::TlsConfig::new_client_insecure().expect("client TLS");
    let mut control = client_tls
        .connect_stream("localhost", tcp)
        .await
        .expect("control TLS handshake");

    rust_frp_core::write_message(&mut control, &Message::Login(login_msg(token)))
        .await
        .expect("send login");
    let login = tokio::time::timeout(
        Duration::from_secs(2),
        rust_frp_core::read_message(&mut control),
    )
    .await
    .expect("login response timeout")
    .expect("read login response");
    assert!(matches!(login, Message::LoginResp(_)));

    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(format!("127.0.0.1:{vhost_https_port}")),
    )
    .await
    .expect("HTTPS vhost listener should start")
    .expect("HTTPS vhost listener accepts before shutdown");

    shutdown.notify_waiters();
    shutdown.notify_one();
    tokio::time::timeout(Duration::from_secs(2), &mut server_task)
        .await
        .expect("server accept loops should stop")
        .expect("server task join");

    assert_refused(vhost_https_port, "HTTPS vhost listener").await;
}
