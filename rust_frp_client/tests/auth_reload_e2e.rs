//! token 热重载传播：旧会话继续使用登录快照，新会话使用新 token。

use rust_frp_config::{AuthConfig, ServerConfig};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_tcp_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind free port");
    listener.local_addr().expect("local addr").port()
}

async fn start_echo_server() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo");
    let port = listener.local_addr().expect("echo addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut read, mut write) = conn.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    port
}

fn server_toml(bind_port: u16, work_port: u16, vhost_port: u16, token: &str) -> String {
    format!(
        r#"
bind_addr = "127.0.0.1"
bind_port = {bind_port}
work_conn_port = {work_port}
vhost_http_port = {vhost_port}
allow_ports = [{{ start = 10000, end = 65535 }}]

[auth]
token = "{token}"
"#
    )
}

fn client_toml(
    bind_port: u16,
    token: &str,
    proxy_name: &str,
    local_port: u16,
    remote_port: u16,
    log_path: &std::path::Path,
) -> String {
    format!(
        r#"
server_addr = "127.0.0.1"
server_port = {bind_port}

[auth]
token = "{token}"

[transport]
tcp_mux = false

[transport.tls]
enable = false

[log]
to = "{}"
level = "info"

[[proxies]]
name = "{proxy_name}"
type = "tcp"
local_ip = "127.0.0.1"
local_port = {local_port}
remote_port = {remote_port}
use_encryption = true
"#,
        log_path.display()
    )
}

async fn wait_for_log(path: &std::path::Path, needle: &str) {
    for _ in 0..100 {
        if std::fs::read_to_string(path).is_ok_and(|text| text.contains(needle)) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("log {} did not contain {needle}", path.display());
}

async fn assert_echo(port: u16, payload: &[u8]) {
    let mut conn = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect proxied port");
    conn.write_all(payload).await.expect("write payload");
    let mut response = vec![0u8; payload.len()];
    conn.read_exact(&mut response).await.expect("read echo");
    assert_eq!(response, payload, "encrypted work conn payload mismatch");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn token_reload_updates_new_sessions_without_breaking_live_sessions() {
    let bind_port = free_tcp_port();
    let work_port = free_tcp_port();
    let vhost_port = free_tcp_port();
    let old_remote_port = free_tcp_port();
    let new_remote_port = free_tcp_port();
    let echo_port = start_echo_server().await;
    let test_dir = std::env::temp_dir().join(format!(
        "rust-frp-auth-reload-{}-{}",
        std::process::id(),
        rust_frp_util::rand_id(8)
    ));
    std::fs::create_dir_all(&test_dir).expect("create test dir");
    let server_config_path = test_dir.join("frps.toml");
    let old_client_path = test_dir.join("old-frpc.toml");
    let new_client_path = test_dir.join("new-frpc.toml");
    let old_client_log = test_dir.join("old-frpc.log");
    let new_client_log = test_dir.join("new-frpc.log");

    std::fs::write(
        &server_config_path,
        server_toml(bind_port, work_port, vhost_port, "old-token"),
    )
    .expect("write initial server config");
    let server_config = ServerConfig {
        bind_addr: "127.0.0.1".to_string(),
        bind_port,
        work_conn_port: Some(work_port),
        vhost_http_port: Some(vhost_port),
        allow_ports: vec![rust_frp_config::PortRange {
            single: None,
            start: Some(10000),
            end: Some(65535),
        }],
        auth: AuthConfig {
            method: "token".to_string(),
            token: Some("old-token".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut server = rust_frp_server::Server::new(
        server_config,
        Some(server_config_path.to_string_lossy().into_owned()),
    )
    .await
    .expect("server construct");
    let shutdown = server.shutdown_handle();
    let (reload_tx, reload_rx) = tokio::sync::mpsc::channel(1);
    server.set_reload_rx(reload_rx);
    let mut server_task = tokio::spawn(async move {
        server.start().await.expect("server start");
    });

    std::fs::write(
        &old_client_path,
        client_toml(
            bind_port,
            "old-token",
            "old-session-proxy",
            echo_port,
            old_remote_port,
            &old_client_log,
        ),
    )
    .expect("write old client config");
    let frpc = env!("CARGO_BIN_EXE_rust_frpc");
    let old_client = ChildGuard(
        Command::new(frpc)
            .arg("-c")
            .arg(&old_client_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn old client"),
    );
    wait_for_log(&old_client_log, "Proxy registered successfully").await;

    std::fs::write(
        &server_config_path,
        server_toml(bind_port, work_port, vhost_port, "new-token"),
    )
    .expect("write reloaded server config");
    reload_tx.send(()).await.expect("send reload signal");
    tokio::time::sleep(Duration::from_millis(200)).await;

    std::fs::write(
        &new_client_path,
        client_toml(
            bind_port,
            "new-token",
            "new-session-proxy",
            echo_port,
            new_remote_port,
            &new_client_log,
        ),
    )
    .expect("write new client config");
    let new_client = ChildGuard(
        Command::new(frpc)
            .arg("-c")
            .arg(&new_client_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn new client"),
    );
    wait_for_log(&new_client_log, "Proxy registered successfully").await;

    assert_echo(old_remote_port, b"old-session-after-reload").await;
    assert_echo(new_remote_port, b"new-session-after-reload").await;

    drop(old_client);
    drop(new_client);
    shutdown.notify_waiters();
    shutdown.notify_one();
    tokio::time::timeout(Duration::from_secs(2), &mut server_task)
        .await
        .expect("server shutdown timeout")
        .expect("server task join");
    let _ = std::fs::remove_dir_all(test_dir);
}
