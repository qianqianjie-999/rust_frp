//! P1-4 TLS 系插件集成测试
//!
//! - https2http / tls2raw：访客 TLS 接入 → 终止 TLS → 明文 echo 回显
//! - https2https：访客 TLS 接入 → 终止 TLS → 重新 TLS → TLS echo 回显（双层 TLS）
//! - 工厂注册与配置校验

use rust_frp_config::PluginConfig;
use rust_frp_plugin::{Plugin, PluginManager};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 启动明文 TCP echo 服务器，返回监听地址
async fn spawn_echo_server() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            if let Ok((conn, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = tokio::io::split(conn);
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        }
    });
    addr
}

/// 启动 TLS echo 服务器（内置自签名证书），返回监听地址
async fn spawn_tls_echo_server() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let tls_config = rust_frp_net::TlsConfig::new_server_with_builtin_cert().unwrap();
    tokio::spawn(async move {
        loop {
            if let Ok((conn, _)) = listener.accept().await {
                let tls_config = tls_config.clone();
                tokio::spawn(async move {
                    if let Ok(tls_conn) = tls_config.accept(conn).await {
                        let (mut r, mut w) = tokio::io::split(tls_conn);
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                    }
                });
            }
        }
    });
    addr
}

/// 模拟访客连接：一端交给插件 handle，返回另一端（测试侧 TCP 流）
async fn visitor_conn_to_plugin(plugin: Box<dyn Plugin>) -> tokio::net::TcpStream {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let accept_task = tokio::spawn(async move {
        let (conn, _) = listener.accept().await.unwrap();
        let _ = tx.send(());
        conn
    });
    let client = tokio::net::TcpStream::connect(addr).await.unwrap();
    rx.await.unwrap();
    let conn = accept_task.await.unwrap();
    tokio::spawn(async move {
        let mut plugin = plugin;
        if let Err(e) = plugin.handle(Box::new(conn)).await {
            log::debug!("plugin handle ended: {:?}", e);
        }
    });
    client
}

/// TLS 客户端接入并断言 echo 回显
async fn assert_tls_echo(client_tcp: tokio::net::TcpStream, payload: &[u8]) {
    let tls_client = rust_frp_net::TlsConfig::new_client_insecure().unwrap();
    let mut tls = tls_client
        .connect_stream("localhost", client_tcp)
        .await
        .expect("TLS handshake with plugin should succeed");

    tls.write_all(payload).await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), tls.read(&mut buf))
        .await
        .expect("echo should arrive")
        .expect("read should succeed");
    assert_eq!(&buf[..n], payload);
}

fn plugin_cfg(r#type: &str, local_addr: &str) -> PluginConfig {
    PluginConfig {
        r#type: r#type.to_string(),
        local_addr: Some(local_addr.to_string()),
        ..Default::default()
    }
}

fn expect_ok<T>(r: Result<T, Box<dyn std::error::Error + Send + Sync>>, ctx: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{} failed: {}", ctx, e),
    }
}

#[tokio::test]
async fn test_https2http_tls_offload_echo() {
    let echo_addr = spawn_echo_server().await;
    let plugin = expect_ok(
        rust_frp_plugin::TlsOffloadPlugin::new(&plugin_cfg("https2http", &echo_addr)),
        "plugin create with builtin cert",
    );

    let client_tcp = visitor_conn_to_plugin(Box::new(plugin)).await;
    assert_tls_echo(client_tcp, b"hello https2http").await;
}

#[tokio::test]
async fn test_tls2raw_same_offload_impl() {
    let echo_addr = spawn_echo_server().await;
    // tls2raw 与 https2http 同一实现（TlsOffloadPlugin）
    let plugin = expect_ok(
        rust_frp_plugin::TlsOffloadPlugin::new(&plugin_cfg("tls2raw", &echo_addr)),
        "tls2raw plugin create",
    );

    let client_tcp = visitor_conn_to_plugin(Box::new(plugin)).await;
    assert_tls_echo(client_tcp, b"tls2raw payload").await;
}

#[tokio::test]
async fn test_https2https_double_tls_echo() {
    let tls_echo_addr = spawn_tls_echo_server().await;
    let plugin = expect_ok(
        rust_frp_plugin::TlsBridgePlugin::new(&plugin_cfg("https2https", &tls_echo_addr)),
        "https2https plugin create",
    );

    let client_tcp = visitor_conn_to_plugin(Box::new(plugin)).await;
    // 数据经插件双层 TLS 到达 TLS echo 服务器并原路返回
    assert_tls_echo(client_tcp, b"double tls hello").await;
}

#[test]
fn test_plugin_factory_registration_and_validation() {
    let mgr = PluginManager::new();

    // 三个类型均已注册，内置证书即可创建
    let echo_addr = "127.0.0.1:9999".to_string();
    for t in ["https2http", "tls2raw", "https2https"] {
        let cfg = plugin_cfg(t, &echo_addr);
        assert!(
            mgr.create_plugin(&cfg).is_ok(),
            "{} should be registered and creatable with builtin cert",
            t
        );
    }

    // 缺 local_addr → 创建失败
    let cfg = PluginConfig {
        r#type: "https2http".to_string(),
        ..Default::default()
    };
    let msg = match mgr.create_plugin(&cfg) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("should fail without local_addr"),
    };
    assert!(msg.contains("local_addr is required"));

    // crt_path 与 key_path 必须成对出现
    let cfg = PluginConfig {
        r#type: "tls2raw".to_string(),
        local_addr: Some(echo_addr),
        crt_path: Some("/nonexistent.crt".to_string()),
        key_path: None,
        ..Default::default()
    };
    assert!(mgr.create_plugin(&cfg).is_err());
}
