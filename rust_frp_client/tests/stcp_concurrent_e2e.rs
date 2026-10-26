//! Real-process STCP concurrency regression:
//! two rust_frpc processes must relay independent TCP streams through one frps.

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_real_frpc_connections_do_not_cross_streams() {
    let token = "stcp-concurrent-e2e-token";
    let bind_port = free_tcp_port();
    let work_port = free_tcp_port();
    let vhost_port = free_tcp_port();
    let echo_port = start_echo_server().await;
    let visitor_port = free_tcp_port();
    let test_dir = std::env::temp_dir().join(format!(
        "rust-frp-stcp-concurrent-{}-{}",
        std::process::id(),
        rust_frp_util::rand_id(8)
    ));
    std::fs::create_dir_all(&test_dir).expect("create test dir");

    let server_config = ServerConfig {
        bind_addr: "127.0.0.1".to_string(),
        bind_port,
        work_conn_port: Some(work_port),
        vhost_http_port: Some(vhost_port),
        auth: AuthConfig {
            method: "token".to_string(),
            token: Some(token.to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut server = rust_frp_server::Server::new(server_config, None)
        .await
        .expect("server construct");
    let shutdown = server.shutdown_handle();
    let mut server_task = tokio::spawn(async move {
        server.start().await.expect("server start");
    });

    let owner_config = test_dir.join("owner.toml");
    let visitor_config = test_dir.join("visitor.toml");
    let owner_log = test_dir.join("owner.log");
    let visitor_log = test_dir.join("visitor.log");
    std::fs::write(
        &owner_config,
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
name = "stcp-concurrent-e2e"
type = "stcp"
local_ip = "127.0.0.1"
local_port = {echo_port}
secret_key = "stcp-concurrent-e2e-secret"
"#,
            owner_log.display()
        ),
    )
    .expect("write owner config");
    std::fs::write(
        &visitor_config,
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

[[visitors]]
name = "stcp-concurrent-e2e-visitor"
type = "stcp"
server_name = "stcp-concurrent-e2e"
bind_addr = "127.0.0.1"
bind_port = {visitor_port}
secret_key = "stcp-concurrent-e2e-secret"
"#,
            visitor_log.display()
        ),
    )
    .expect("write visitor config");

    let frpc = env!("CARGO_BIN_EXE_rust_frpc");
    let owner = ChildGuard(
        Command::new(frpc)
            .arg("-c")
            .arg(&owner_config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn owner frpc"),
    );
    let visitor = ChildGuard(
        Command::new(frpc)
            .arg("-c")
            .arg(&visitor_config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn visitor frpc"),
    );

    let mut ready = false;
    for _ in 0..100 {
        let owner_ready = std::fs::read_to_string(&owner_log)
            .is_ok_and(|log| log.contains("Proxy registered successfully"));
        let visitor_ready = std::fs::read_to_string(&visitor_log)
            .is_ok_and(|log| log.contains("listening on 127.0.0.1"));
        if owner_ready && visitor_ready {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "owner/visitor frpc did not become ready");

    let rounds = 5;
    let connections = 20;
    for round in 0..rounds {
        let mut tasks = Vec::new();
        for index in 0..connections {
            tasks.push(tokio::spawn(async move {
                let id = round * connections + index;
                let payload = format!("req-{id:03}-").into_bytes();
                let payload = [payload.as_slice(), &[b'x'; 64 - 8]].concat();
                let mut conn = tokio::net::TcpStream::connect(format!("127.0.0.1:{visitor_port}"))
                    .await
                    .expect("connect visitor");
                conn.write_all(&payload).await.expect("write payload");
                let mut response = vec![0u8; payload.len()];
                conn.read_exact(&mut response).await.expect("read echo");
                assert_eq!(response, payload, "STCP TCP streams crossed at id {id}");
            }));
        }
        for task in tasks {
            task.await.expect("connection task");
        }
    }

    drop(owner);
    drop(visitor);
    shutdown.notify_waiters();
    shutdown.notify_one();
    tokio::time::timeout(Duration::from_secs(2), &mut server_task)
        .await
        .expect("server shutdown timeout")
        .expect("server task join");
    let _ = std::fs::remove_dir_all(test_dir);
}
