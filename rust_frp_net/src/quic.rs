//! # QUIC 传输（quinn + rustls 0.23，TLS 1.3 强制）
//!
//! 对齐原版 frp 的 `transport.protocol = "quic"`：
//!
//! - **服务端**：在 `quic_bind_port`（UDP）上起一个 QUIC endpoint；每条 QUIC
//!   连接上可承载**多条双向流**，每条流等价于一条「逻辑连接」（控制连接 / 工作连接），
//!   由服务端按流上的首条消息分派（见 `rust_frp_server`）。
//! - **客户端**：建立一个 QUIC 连接（[`QuicSession`]），控制连接与后续工作连接
//!   都作为该连接上的独立双向流打开，省去重复握手。
//! - **ALPN**：`frp`（与原版一致）。
//!
//! ## TLS 说明
//!
//! QUIC 强制 TLS 1.3，因此本模块**不复用** `TlsConfig`（其内部是 tokio-rustls
//! 0.25 对应的 rustls 0.22 配置对象，类型与 quinn 所需的 rustls 0.23 不兼容），
//! 而是按相同语义（自签 / 自定义证书 / 受信 CA / 跳过校验）在此重新构造 rustls 0.23 配置。
//!
//! ## 与 TCP 的差异
//!
//! | 维度 | TCP / KCP | QUIC |
//! |------|-----------|------|
//! | 工作连接 | 独立连接（TCP）或独立 conv（KCP） | 同一 QUIC 连接上的新双向流 |
//! | 加密 | 可选（TLS 开关） | 始终 TLS 1.3（协议内建） |
//! | 传输可靠性 | 由传输层保证 | 内建多路复用 + 0-RTT 重连（本实现用 1-RTT） |

use crate::{AnyConn, FrpConn, NetError};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// QUIC 协商的应用层协议名（ALPN），与原版 frp 一致
pub const QUIC_ALPN: &[u8] = b"frp";

/// QUIC 传输参数（对齐原版 `transport.quic.*` 语义）
#[derive(Debug, Clone)]
pub struct QuicOptions {
    /// 空闲超时；`None` 表示禁用（不主动断开空闲连接）
    pub max_idle_timeout: Option<Duration>,
    /// 允许对端并发打开的双向流上限
    pub max_incoming_streams: u32,
    /// 保活间隔；`None` 表示禁用
    pub keep_alive_interval: Option<Duration>,
}

impl Default for QuicOptions {
    fn default() -> Self {
        Self {
            // 与原版 frp 默认对齐：30s 空闲超时 / 10 万并发流 / 不主动保活
            max_idle_timeout: Some(Duration::from_secs(30)),
            max_incoming_streams: 100_000,
            keep_alive_interval: None,
        }
    }
}

impl QuicOptions {
    /// 由 `transport.quic` 的原始配置字段构造（`None` 用默认值，`0` 视为禁用）
    pub fn from_config(
        max_idle_timeout_secs: Option<u64>,
        max_incoming_streams: Option<u32>,
        keepalive_period_secs: Option<u64>,
    ) -> Self {
        let defaults = Self::default();
        Self {
            max_idle_timeout: match max_idle_timeout_secs {
                Some(0) => None,
                Some(s) => Some(Duration::from_secs(s)),
                None => defaults.max_idle_timeout,
            },
            max_incoming_streams: max_incoming_streams
                .filter(|n| *n > 0)
                .unwrap_or(defaults.max_incoming_streams),
            keep_alive_interval: match keepalive_period_secs {
                Some(s) if s > 0 => Some(Duration::from_secs(s)),
                _ => None,
            },
        }
    }
}

fn transport_config(opts: &QuicOptions) -> Arc<quinn::TransportConfig> {
    let mut tc = quinn::TransportConfig::default();
    if let Some(idle) = opts.max_idle_timeout {
        match quinn::IdleTimeout::try_from(idle) {
            Ok(v) => {
                tc.max_idle_timeout(Some(v));
            }
            Err(_) => {
                log::warn!("QUIC max_idle_timeout out of range, disabling idle timeout");
                tc.max_idle_timeout(None);
            }
        }
    } else {
        tc.max_idle_timeout(None);
    }
    tc.max_concurrent_bidi_streams(quinn::VarInt::from_u32(opts.max_incoming_streams));
    tc.keep_alive_interval(opts.keep_alive_interval);
    Arc::new(tc)
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, NetError> {
    CertificateDer::pem_file_iter(path)
        .map_err(|e| NetError::PemDecode(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| NetError::PemDecode(e.to_string()))
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, NetError> {
    // from_pem 自动识别 PKCS8 / RSA(PKCS1) / SEC1，与旧实现「先 pkcs8 后 rsa 兜底」一致
    PrivateKeyDer::from_pem_file(path).map_err(|e| NetError::PemDecode(e.to_string()))
}

/// 构造 QUIC 服务端配置
///
/// - 提供 `cert_file` + `key_file` 时使用自定义证书；
/// - 否则使用**运行时生成**的自签证书（仅加密，不认证身份）。
pub fn build_server_config(
    cert_file: Option<&str>,
    key_file: Option<&str>,
    opts: &QuicOptions,
) -> Result<quinn::ServerConfig, NetError> {
    crate::ensure_crypto_provider();
    let mut rustls_cfg = match (cert_file, key_file) {
        (Some(c), Some(k)) => rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(load_certs(c)?, load_key(k)?)
            .map_err(|e| NetError::Other(format!("QUIC server cert rejected: {e}")))?,
        _ => {
            log::warn!(
                "QUIC is using a RUNTIME-GENERATED self-signed certificate: \
                 encryption only, server identity NOT authenticated. \
                 Configure transport.tls.cert_file/key_file to pin your own certificate."
            );
            let cert = rcgen::generate_simple_self_signed(vec![
                "frp-server.local".to_string(),
                "localhost".to_string(),
            ])
            .map_err(|e| NetError::Other(format!("generate self-signed certificate: {e}")))?;
            let cert_der = cert.cert.der().to_owned();
            let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der.into())
                .map_err(|e| NetError::Other(format!("QUIC self-signed cert rejected: {e}")))?
        }
    };
    rustls_cfg.alpn_protocols = vec![QUIC_ALPN.to_vec()];

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_cfg)
        .map_err(|e| NetError::Other(format!("QUIC server crypto config: {e}")))?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    cfg.transport_config(transport_config(opts));
    Ok(cfg)
}

/// 构造 QUIC 客户端配置
///
/// - 提供 `ca_file`：用该 CA 校验服务端证书（认证）；
/// - `insecure = true`：跳过证书校验（仅加密，**不认证**，慎用）。
pub fn build_client_config(
    ca_file: Option<&str>,
    insecure: bool,
    opts: &QuicOptions,
) -> Result<quinn::ClientConfig, NetError> {
    crate::ensure_crypto_provider();
    let mut rustls_cfg = if let Some(ca) = ca_file {
        let mut roots = rustls::RootCertStore::empty();
        for cert in load_certs(ca)? {
            roots
                .add(cert)
                .map_err(|e| NetError::Other(format!("QUIC trusted CA rejected: {e}")))?;
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(Arc::new(roots))
            .with_no_client_auth()
    } else if insecure {
        log::warn!(
            "QUIC client configured with certificate verification DISABLED: \
             traffic is encrypted but the server identity is NOT authenticated"
        );
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(QuicSkipVerification))
            .with_no_client_auth()
    } else {
        return Err(NetError::Other(
            "QUIC client requires trusted_ca_file (or skip_verify = true)".into(),
        ));
    };
    rustls_cfg.alpn_protocols = vec![QUIC_ALPN.to_vec()];

    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg)
        .map_err(|e| NetError::Other(format!("QUIC client crypto config: {e}")))?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    cfg.transport_config(transport_config(opts));
    Ok(cfg)
}

/// 跳过 QUIC 服务端证书校验（对齐 TLS 的 `skip_verify` 语义）
#[derive(Debug)]
struct QuicSkipVerification;

impl ServerCertVerifier for QuicSkipVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// 一条 QUIC 双向流，桥接为 FRP 连接（`AsyncRead + AsyncWrite + FrpConn`）
pub struct QuicConn {
    send: SendStream,
    recv: RecvStream,
    remote: SocketAddr,
}

impl QuicConn {
    /// 由 quinn 的发送/接收半流构造
    pub fn new(send: SendStream, recv: RecvStream, remote: SocketAddr) -> Self {
        Self { send, recv, remote }
    }
}

impl AsyncRead for QuicConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // 显式走 tokio 的 AsyncRead（quinn 的半流自带同名 inherent 方法，需限定 trait）
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for QuicConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

impl FrpConn for QuicConn {
    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote)
    }
}

/// QUIC 服务端监听器
pub struct QuicListener {
    endpoint: Endpoint,
}

impl QuicListener {
    /// 在 `addr` 上绑定 QUIC endpoint
    pub fn bind(addr: SocketAddr, config: quinn::ServerConfig) -> Result<Self, NetError> {
        let endpoint = Endpoint::server(config, addr)
            .map_err(|e| NetError::Other(format!("QUIC bind {} failed: {e}", addr)))?;
        Ok(Self { endpoint })
    }

    /// 实际绑定的本地地址（便于测试用 :0 端口）
    pub fn local_addr(&self) -> Result<SocketAddr, NetError> {
        self.endpoint
            .local_addr()
            .map_err(|e| NetError::Other(format!("QUIC local_addr: {e}")))
    }

    /// 接受一条新的 QUIC 连接（后续在其上接受双向流）
    pub async fn accept(&self) -> Result<QuicConnection, NetError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| NetError::Other("QUIC endpoint closed".into()))?;
        let remote = incoming.remote_address();
        let conn = incoming
            .await
            .map_err(|e| NetError::Other(format!("QUIC accept from {remote}: {e}")))?;
        log::debug!("accepted QUIC connection from {}", remote);
        Ok(QuicConnection { conn, remote })
    }
}

/// 一条已建立的 QUIC 连接（服务端视角），可在其上接受多条双向流
pub struct QuicConnection {
    conn: Connection,
    remote: SocketAddr,
}

impl QuicConnection {
    /// 对端地址
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote
    }

    /// 连接是否已关闭
    pub fn is_closed(&self) -> bool {
        self.conn.close_reason().is_some()
    }

    /// 接受一条由对端打开的双向流（等价于一条逻辑连接）
    pub async fn accept_stream(&self) -> Result<QuicConn, NetError> {
        let (send, recv) = self
            .conn
            .accept_bi()
            .await
            .map_err(|e| NetError::Other(format!("QUIC accept stream: {e}")))?;
        Ok(QuicConn::new(send, recv, self.remote))
    }
}

/// QUIC 客户端会话：持有一条 QUIC 连接与底层 endpoint
///
/// endpoint 必须随会话存活（drop 会关闭连接），故与连接一同持有。
pub struct QuicSession {
    conn: Connection,
    _endpoint: Endpoint,
    remote: SocketAddr,
}

impl QuicSession {
    /// 建立到服务端的 QUIC 连接
    pub async fn connect(
        addr: SocketAddr,
        server_name: &str,
        client_config: quinn::ClientConfig,
    ) -> Result<Self, NetError> {
        let mut endpoint = Endpoint::client(
            "0.0.0.0:0"
                .parse()
                .expect("constant bind address is always valid"),
        )
        .map_err(|e| NetError::Other(format!("QUIC client endpoint: {e}")))?;
        endpoint.set_default_client_config(client_config);
        let conn = endpoint
            .connect(addr, server_name)
            .map_err(|e| NetError::Other(format!("QUIC connect {addr}: {e}")))?
            .await
            .map_err(|e| NetError::Other(format!("QUIC handshake with {addr}: {e}")))?;
        log::debug!("established QUIC connection to {}", addr);
        Ok(Self {
            conn,
            _endpoint: endpoint,
            remote: addr,
        })
    }

    /// 对端地址
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote
    }

    /// 打开一条新的双向流（控制连接 / 工作连接）
    pub async fn open_stream(&self) -> Result<AnyConn, NetError> {
        let (send, recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| NetError::Other(format!("QUIC open stream: {e}")))?;
        Ok(Box::new(QuicConn::new(send, recv, self.remote)))
    }
}

#[async_trait::async_trait]
impl crate::Session for QuicSession {
    async fn open_stream(&self) -> Result<AnyConn, NetError> {
        QuicSession::open_stream(self).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn opts() -> QuicOptions {
        QuicOptions::default()
    }

    /// 服务端：接受一条连接、一条流，读满 `n` 字节后原样回写
    async fn spawn_echo(listener: QuicListener, n: usize) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let conn = listener.accept().await.expect("accept connection");
            let mut stream = conn.accept_stream().await.expect("accept stream");
            let mut buf = vec![0u8; n];
            stream.read_exact(&mut buf).await.expect("read payload");
            stream.write_all(&buf).await.expect("write echo");
            stream.flush().await.expect("flush");
            // 保持连接存活到对端读完
            tokio::time::sleep(Duration::from_millis(300)).await;
        })
    }

    #[tokio::test]
    async fn quic_stream_roundtrip_echo() {
        let server_cfg = build_server_config(None, None, &opts()).expect("server config");
        let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = spawn_echo(listener, 11).await;

        let client_cfg = build_client_config(None, true, &opts()).expect("client config");
        let session = QuicSession::connect(addr, "localhost", client_cfg)
            .await
            .expect("connect");
        let mut stream = session.open_stream().await.expect("open stream");
        stream.write_all(b"hello-quic!").await.unwrap();
        let mut buf = [0u8; 11];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello-quic!");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn quic_multiple_streams_are_independent() {
        let server_cfg = build_server_config(None, None, &opts()).expect("server config");
        let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
        let addr = listener.local_addr().unwrap();

        // 服务端：一条连接上并发处理 4 条流，每条回写首字节
        let server = tokio::spawn(async move {
            let conn = listener.accept().await.expect("accept connection");
            let mut handles = Vec::new();
            for _ in 0..4 {
                let mut stream = conn.accept_stream().await.expect("accept stream");
                handles.push(tokio::spawn(async move {
                    let mut b = [0u8; 1];
                    stream.read_exact(&mut b).await.unwrap();
                    stream.write_all(&b).await.unwrap();
                    stream.flush().await.unwrap();
                }));
            }
            for h in handles {
                h.await.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        });

        let client_cfg = build_client_config(None, true, &opts()).expect("client config");
        let session = Arc::new(
            QuicSession::connect(addr, "localhost", client_cfg)
                .await
                .expect("connect"),
        );
        let mut tasks = Vec::new();
        for i in 0u8..4 {
            let session = session.clone();
            tasks.push(tokio::spawn(async move {
                let mut stream = session.open_stream().await.expect("open stream");
                stream.write_all(&[i]).await.unwrap();
                let mut b = [0u8; 1];
                stream.read_exact(&mut b).await.unwrap();
                assert_eq!(b[0], i);
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn quic_rejects_unverified_client_without_ca() {
        // 未提供 CA 且未显式 insecure → 拒绝构造客户端配置（fail-closed）
        let err = build_client_config(None, false, &opts()).err();
        assert!(err.is_some());
    }

    #[tokio::test]
    async fn quic_large_payload_flows_across_stream() {
        // 1 MiB 载荷，验证流控下不丢字节
        const N: usize = 1024 * 1024;
        let server_cfg = build_server_config(None, None, &opts()).expect("server config");
        let listener = QuicListener::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = spawn_echo(listener, N).await;

        let client_cfg = build_client_config(None, true, &opts()).expect("client config");
        let session = QuicSession::connect(addr, "localhost", client_cfg)
            .await
            .expect("connect");
        let mut stream = session.open_stream().await.expect("open stream");
        let payload = vec![0xA5u8; N];
        stream.write_all(&payload).await.unwrap();
        let mut got = vec![0u8; N];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload);

        server.await.unwrap();
    }
}
