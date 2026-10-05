//! mTLS（双向证书认证）回归：证书签发 + 握手正/负例（TCP 与 QUIC 两条路径）
//!
//! 全部在临时目录内自签证书完成，**不依赖线上材料、不需要 openssl**。
//!
//! 覆盖的关键语义：
//! 1. 合法客户端证书 + `require = true` → 握手成功（**正例**）
//! 2. `require = true` 但客户端不出示证书 → 必须失败
//! 3. `require = false` 但客户端不出示证书 → 必须成功（灰度期语义，**不是**跳过校验）
//! 4. 客户端证书由**别的 CA** 签发 → 必须失败
//! 5. 客户端证书 EKU 是 `serverAuth`（不是 `clientAuth`）→ 必须失败
//! 6. CA 文件不存在 → 构造即失败
//! 7. QUIC 路径同样受保护（设计稿点名的"第二个触点"，不得遗漏）

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rust_frp_net::{QuicListener, QuicOptions, QuicSession, TlsConfig};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 临时证书目录（Drop 时清理）
struct TempPems {
    dir: PathBuf,
}

impl TempPems {
    fn new(tag: &str) -> Self {
        // ⚠️ 目录名必须**每次调用唯一**：测试并行跑在同一进程里，若共用
        // `...-{pid}` 目录，某个用例 Drop 时会把别的用例正在读的证书删掉/覆盖，
        // 表现为随机的 "No such file" 或 InconsistentKeys(KeyMismatch)。
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "frp-mtls-{}-{}-{}-{}",
            tag,
            std::process::id(),
            seq,
            nanos
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self { dir }
    }

    fn write(&self, name: &str, content: &str) -> PathBuf {
        let p = self.dir.join(name);
        std::fs::write(&p, content).expect("write pem");
        p
    }
}

impl Drop for TempPems {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn gen_ca(cn: &str) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
        .distinguished_name
        .push(DnType::CommonName, cn.to_string());
    let cert = params.self_signed(&key).expect("self-signed ca");
    (cert, key)
}

fn gen_leaf(
    cn: &str,
    eku: ExtendedKeyUsagePurpose,
    sans: Vec<String>,
    ca: &rcgen::Certificate,
    ca_key: &KeyPair,
) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(sans).expect("leaf params");
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![eku];
    params
        .distinguished_name
        .push(DnType::CommonName, cn.to_string());
    let cert = params.signed_by(&key, ca, ca_key).expect("signed leaf");
    (cert, key)
}

/// 一套完整的实验材料：受信 CA + 服务端证书 + 三种客户端证书
struct Lab {
    ca: PathBuf,
    server_crt: PathBuf,
    server_key: PathBuf,
    client_crt: PathBuf,
    client_key: PathBuf,
    /// 由另一（不受信）CA 签发
    evil_client_crt: PathBuf,
    evil_client_key: PathBuf,
    /// 由本 CA 签发，但 EKU 为 serverAuth
    wrong_eku_client_crt: PathBuf,
    wrong_eku_client_key: PathBuf,
    _pems: TempPems,
}

fn lab() -> Lab {
    let pems = TempPems::new("lab");

    let (ca_cert, ca_key) = gen_ca("frp test CA");
    let (srv_cert, srv_key) = gen_leaf(
        "frp-server",
        ExtendedKeyUsagePurpose::ServerAuth,
        vec!["localhost".to_string()],
        &ca_cert,
        &ca_key,
    );
    let (cli_cert, cli_key) = gen_leaf(
        "frp-cli-32",
        ExtendedKeyUsagePurpose::ClientAuth,
        Vec::new(),
        &ca_cert,
        &ca_key,
    );
    let (we_cert, we_key) = gen_leaf(
        "frp-cli-wrong-eku",
        ExtendedKeyUsagePurpose::ServerAuth,
        Vec::new(),
        &ca_cert,
        &ca_key,
    );
    let (evil_ca_cert, evil_ca_key) = gen_ca("evil CA");
    let (evil_cert, evil_key) = gen_leaf(
        "frp-cli-evil",
        ExtendedKeyUsagePurpose::ClientAuth,
        Vec::new(),
        &evil_ca_cert,
        &evil_ca_key,
    );

    Lab {
        ca: pems.write("ca.crt", &ca_cert.pem()),
        server_crt: pems.write("server.crt", &srv_cert.pem()),
        server_key: pems.write("server.key", &srv_key.serialize_pem()),
        client_crt: pems.write("client.crt", &cli_cert.pem()),
        client_key: pems.write("client.key", &cli_key.serialize_pem()),
        evil_client_crt: pems.write("evil-client.crt", &evil_cert.pem()),
        evil_client_key: pems.write("evil-client.key", &evil_key.serialize_pem()),
        wrong_eku_client_crt: pems.write("wrong-eku.crt", &we_cert.pem()),
        wrong_eku_client_key: pems.write("wrong-eku.key", &we_key.serialize_pem()),
        _pems: pems,
    }
}

fn s(p: &Path) -> &str {
    p.to_str().expect("utf-8 path")
}

/// 在本地回环上跑一次完整 TLS 握手，返回双方是否都成功
async fn tls_handshake(server: &TlsConfig, client: &TlsConfig) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let srv = server.clone();
    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
        srv.accept(stream).await.map_err(|e| e.to_string())?;
        Ok::<(), String>(())
    });

    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| e.to_string())?;
    let client_res = client
        .connect("localhost", stream)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string());
    let server_res = handle.await.map_err(|e| e.to_string())?;

    client_res?;
    server_res
}

/// 服务端：`require_client_cert = true`
fn server_require(lab: &Lab) -> TlsConfig {
    TlsConfig::new_server(
        s(&lab.server_crt),
        s(&lab.server_key),
        Some(s(&lab.ca)),
        true,
    )
    .expect("server tls (require)")
}

/// 服务端：`require_client_cert = false`（灰度期）
fn server_optional(lab: &Lab) -> TlsConfig {
    TlsConfig::new_server(
        s(&lab.server_crt),
        s(&lab.server_key),
        Some(s(&lab.ca)),
        false,
    )
    .expect("server tls (optional)")
}

// ─────────────────────────── TCP ───────────────────────────

#[tokio::test]
async fn mtls_handshake_succeeds_with_valid_client_cert() {
    let lab = lab();
    let client =
        TlsConfig::new_client_with_ca_and_cert(s(&lab.ca), s(&lab.client_crt), s(&lab.client_key))
            .expect("client tls");
    let res = tls_handshake(&server_require(&lab), &client).await;
    assert!(res.is_ok(), "合法 mTLS 握手必须成功，实际: {res:?}");
}

#[tokio::test]
async fn mtls_rejects_client_without_certificate_when_required() {
    let lab = lab();
    let client = TlsConfig::new_client_with_ca_file(s(&lab.ca)).expect("client tls");
    let res = tls_handshake(&server_require(&lab), &client).await;
    assert!(res.is_err(), "require=true 时未出示证书必须握手失败");
}

#[tokio::test]
async fn mtls_allows_client_without_certificate_when_not_required() {
    let lab = lab();
    let client = TlsConfig::new_client_with_ca_file(s(&lab.ca)).expect("client tls");
    let res = tls_handshake(&server_optional(&lab), &client).await;
    assert!(
        res.is_ok(),
        "require=false 是灰度语义（未出示放行），不是跳过校验，实际: {res:?}"
    );
}

#[tokio::test]
async fn mtls_rejects_client_cert_from_other_ca() {
    let lab = lab();
    let client = TlsConfig::new_client_with_ca_and_cert(
        s(&lab.ca),
        s(&lab.evil_client_crt),
        s(&lab.evil_client_key),
    )
    .expect("client tls");
    let res = tls_handshake(&server_require(&lab), &client).await;
    assert!(res.is_err(), "别家 CA 签发的客户端证书必须被拒");
}

#[tokio::test]
async fn mtls_rejects_client_cert_with_server_auth_eku() {
    let lab = lab();
    let client = TlsConfig::new_client_with_ca_and_cert(
        s(&lab.ca),
        s(&lab.wrong_eku_client_crt),
        s(&lab.wrong_eku_client_key),
    )
    .expect("client tls");
    let res = tls_handshake(&server_require(&lab), &client).await;
    assert!(res.is_err(), "EKU 为 serverAuth 的客户端证书必须被拒");
}

#[tokio::test]
async fn mtls_server_rejects_missing_ca_file() {
    let lab = lab();
    let missing = "/nonexistent/frp-mtls-ca.crt";
    let res = TlsConfig::new_server(s(&lab.server_crt), s(&lab.server_key), Some(missing), true);
    assert!(res.is_err(), "CA 文件不存在时构造服务端 TLS 必须报错");
}

#[tokio::test]
async fn mtls_ca_without_require_still_verifies_presented_cert() {
    // require=false 只是"允许不出示"；一旦出示，链仍必须可信。
    let lab = lab();
    let client = TlsConfig::new_client_with_ca_and_cert(
        s(&lab.ca),
        s(&lab.evil_client_crt),
        s(&lab.evil_client_key),
    )
    .expect("client tls");
    let res = tls_handshake(&server_optional(&lab), &client).await;
    assert!(
        res.is_err(),
        "require=false 不得放宽链校验：别家 CA 的证书依旧必须被拒"
    );
}

// ─────────────────────────── QUIC ───────────────────────────

/// QUIC 客户端能否真正用起来（握手 + 一次流往返）
async fn quic_usable(addr: std::net::SocketAddr, cfg: quinn::ClientConfig) -> bool {
    let connected = tokio::time::timeout(
        Duration::from_secs(5),
        QuicSession::connect(addr, "localhost", cfg),
    )
    .await;
    let session = match connected {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            eprintln!("[debug] QUIC connect error: {e}");
            return false;
        }
        Err(e) => {
            eprintln!("[debug] QUIC connect timeout: {e}");
            return false;
        }
    };
    let rt = tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = session.open_stream().await?;
        stream.write_all(b"ping").await?;
        stream.flush().await?;
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await;
    match rt {
        Ok(Ok(())) => true,
        other => {
            eprintln!("[debug] QUIC stream roundtrip failed: {other:?}");
            false
        }
    }
}

fn quic_server_cfg(lab: &Lab, require: bool) -> quinn::ServerConfig {
    rust_frp_net::build_quic_server_config(
        Some(s(&lab.server_crt)),
        Some(s(&lab.server_key)),
        Some(s(&lab.ca)),
        require,
        &QuicOptions::default(),
    )
    .expect("quic server config")
}

#[tokio::test]
async fn quic_mtls_handshake_succeeds_with_valid_client_cert() {
    let lab = lab();
    let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap(), quic_server_cfg(&lab, true))
        .expect("bind");
    let addr = listener.local_addr().unwrap();
    let srv = tokio::spawn(async move {
        // ⚠️ conn 必须活到 sleep 结束：一旦 drop，quinn 会立刻以 code 0 关闭连接，
        // 客户端会看到 ConnectionLost(ApplicationClosed) 而不是回显数据。
        let Ok(conn) = listener.accept().await else {
            return;
        };
        if let Ok(mut stream) = conn.accept_stream().await {
            let mut buf = [0u8; 4];
            if stream.read_exact(&mut buf).await.is_ok() {
                let _ = stream.write_all(&buf).await;
                let _ = stream.flush().await;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    let cfg = rust_frp_net::build_quic_client_config(
        Some(s(&lab.ca)),
        false,
        Some((s(&lab.client_crt), s(&lab.client_key))),
        &QuicOptions::default(),
    )
    .expect("quic client config");
    assert!(quic_usable(addr, cfg).await, "QUIC mTLS 正例必须可用");
    srv.abort();
}

#[tokio::test]
async fn quic_mtls_rejects_client_without_certificate_when_required() {
    let lab = lab();
    let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap(), quic_server_cfg(&lab, true))
        .expect("bind");
    let addr = listener.local_addr().unwrap();
    let srv = tokio::spawn(async move {
        let _ = listener.accept().await;
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let cfg = rust_frp_net::build_quic_client_config(
        Some(s(&lab.ca)),
        false,
        None,
        &QuicOptions::default(),
    )
    .expect("quic client config");
    assert!(
        !quic_usable(addr, cfg).await,
        "QUIC require=true 时未出示证书必须不可用（QUIC 是 mTLS 的第二个触点，不得遗漏）"
    );
    srv.abort();
}
