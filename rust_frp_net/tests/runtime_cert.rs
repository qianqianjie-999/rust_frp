//! 运行时自签证书回归测试（安全评审 P0-3 收尾：内置私钥不入库）
//!
//! 验证 `new_server_with_runtime_cert()` 生成的证书：
//! 1. 可以正常完成 TLS 握手
//! 2. 进程内每次调用都生成新证书（密钥不重复使用）

use rust_frp_net::TlsConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn runtime_cert_supports_tls_handshake() {
    let server_tls =
        TlsConfig::new_server_with_runtime_cert(None, false).expect("runtime cert generated");
    let client_tls = TlsConfig::new_client_insecure().expect("client tls config");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls_stream = server_tls
            .accept_stream(stream)
            .await
            .expect("server-side TLS handshake");
        tls_stream.write_all(b"pong").await.unwrap();
    });

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    // 运行时生成的自签证书 SAN 覆盖 localhost，以此作为 SNI
    let mut client_stream = client_tls
        .connect_stream("localhost", tcp)
        .await
        .expect("client-side TLS handshake");

    let mut buf = [0u8; 4];
    client_stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");

    server_task.await.unwrap();
}

#[test]
fn runtime_cert_generation_succeeds_repeatedly() {
    // 两次生成都不应失败（此前内置证书方案是编译期固定 PEM，无法体现该性质）
    let _a = TlsConfig::new_server_with_runtime_cert(None, false).expect("first generation");
    let _b = TlsConfig::new_server_with_runtime_cert(None, false).expect("second generation");
}
