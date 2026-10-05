//! FRP 网络层模块
//!
//! 该模块提供了 FRP (Fast Reverse Proxy) 的核心网络抽象，包括：
//!
//! ## 主要组件
//!
//! 1. **连接抽象 (FrpConn trait)**
//!    - 统一的异步 I/O 接口，支持 TCP、TLS、WebSocket 等多种连接类型
//!    - 实现了 `AsyncRead` 和 `AsyncWrite` trait，便于数据流操作
//!
//! 2. **TLS 加密支持**
//!    - 支持自定义证书与运行时生成的自签名证书（内存中，不落盘、不入库）
//!    - 客户端可配置信任指定 CA 证书（trusted_ca_file）
//!
//! 3. **WebSocket 支持**
//!    - 支持通过 WebSocket 协议进行连接，适用于复杂网络环境
//!
//! 4. **连接池管理**
//!    - 支持 TCP 连接复用，减少连接建立开销
//!    - 支持连接池配置（大小、超时、空闲时间等）
//!
//! ## 安全性
//!
//! - TLS 1.2 及以上版本
//! - 未配置证书时服务端使用运行时生成的自签名证书（仅加密，不认证身份）
//! - 生产环境请配置自定义证书

use futures_util::{Sink, Stream};
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{
    TcpListener as TokioTcpListener, TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket,
};
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::UnixTime;
use tokio_rustls::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
};
use tokio_rustls::rustls::DigitallySignedStruct;
use tokio_rustls::rustls::Error as TlsError;
use tokio_rustls::rustls::SignatureScheme;
use tokio_rustls::{client, server, TlsAcceptor, TlsConnector};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::WebSocketStream;

pub mod mux;
pub use mux::{MuxSession, TCP_MUX_MAGIC};

pub mod stun;
pub use stun::{
    classify_nat_feature, default_stun_socket_addrs, discover_from_server,
    discover_public_endpoint, local_outbound_ip, NatFeature,
};

pub mod kcp_stream;
pub use kcp_stream::KcpStream;

pub mod quic;
pub use quic::{
    build_client_config as build_quic_client_config,
    build_server_config as build_quic_server_config, QuicConn, QuicConnection, QuicListener,
    QuicOptions, QuicSession, QUIC_ALPN,
};

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    Tls(#[from] tokio_rustls::rustls::Error),
    #[error("PEM decode error: {0}")]
    PemDecode(String),
    #[error("not a TLS server config")]
    NotServerConfig,
    #[error("not a TLS client config")]
    NotClientConfig,
    #[error("TLS config not set")]
    TlsConfigNotSet,
    #[error("{0}")]
    Other(String),
}

/// 网络连接 trait
#[async_trait::async_trait]
pub trait FrpConn: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {
    fn remote_addr(&self) -> Option<SocketAddr>;
}

/// 类型擦除的连接（TCP/TLS/KCP/WebSocket 统一类型）
///
/// `Box<dyn FrpConn>` 自动满足 AsyncRead + AsyncWrite + Unpin + Send，
/// 可直接用于消息读写与 bridge_streams 桥接。
pub type AnyConn = Box<dyn FrpConn>;

/// 已装箱的类型擦除连接同样满足 FrpConn（支持多层包装，如 EncryptedStream）
impl FrpConn for Box<dyn FrpConn> {
    fn remote_addr(&self) -> Option<SocketAddr> {
        (**self).remote_addr()
    }
}

/// 可打开多条逻辑连接流的上层会话（tcp_mux 的 yamux 会话、QUIC 连接）
///
/// 客户端借此把「控制连接」与「工作连接」复用在同一底层连接上：
/// 一条会话可反复 `open_stream` 得到彼此独立的「逻辑连接」。
#[async_trait::async_trait]
pub trait Session: Send + Sync {
    /// 打开一条新的逻辑连接流
    async fn open_stream(&self) -> Result<AnyConn, NetError>;
}

/// frp 传输层 WebSocket 握手路径（与原版 frp 的 `FrpWebsocketPath` 一致）
///
/// `websocket` / `wss` 传输的客户端在完成 TCP（及可选 TLS）握手后，向
/// `GET <FRP_WS_PATH>` 发起 WebSocket 升级；服务端据此路径前缀识别并升级。
pub const FRP_WS_PATH: &str = "/~!frp";

/// 实现 TokioTcpStream 的 FrpConn trait
impl FrpConn for TokioTcpStream {
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.peer_addr().ok()
    }
}

/// 实现 server::TlsStream<TokioTcpStream> 的 FrpConn trait
impl FrpConn for server::TlsStream<TokioTcpStream> {
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.get_ref().0.peer_addr().ok()
    }
}

/// 实现 client::TlsStream<TokioTcpStream> 的 FrpConn trait
impl FrpConn for client::TlsStream<TokioTcpStream> {
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.get_ref().0.peer_addr().ok()
    }
}

/// WebSocket 连接
///
/// 把 WebSocket 的**帧**语义适配成**字节流**语义（`AsyncRead`/`AsyncWrite`），
/// 使上层 frp 协议栈（4 字节长度前缀 + JSON）无需感知分帧。
///
/// # 写入语义
///
/// `Sink`（tokio-tungstenite）在 `start_send` 之后必须 `poll_flush` 才会真正
/// 落到 TCP 上；而 frp 上层只调用 `write_all`（不 flush）。因此这里在
/// `poll_write` 内主动驱动 flush，并用 `write_pending` 记录「帧已提交但还没
/// flush 完」的长度，避免调用方重试时重复发送。
pub struct WebSocketConn<S> {
    stream: WebSocketStream<S>,
    remote_addr: SocketAddr,
    read_buf: Vec<u8>,
    /// 已 `start_send` 但尚未 flush 完成的帧长度（用于 poll_write 重入）
    write_pending: Option<usize>,
}

impl<S> WebSocketConn<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// 创建新的 WebSocket 连接
    ///
    /// # 参数
    ///
    /// * `stream` - WebSocket 流
    /// * `remote_addr` - 远程地址
    pub fn new(stream: WebSocketStream<S>, remote_addr: SocketAddr) -> Self {
        Self {
            stream,
            remote_addr,
            read_buf: Vec::new(),
            write_pending: None,
        }
    }
}

impl<S> AsyncRead for WebSocketConn<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.read_buf.is_empty() {
            let len = std::cmp::min(self.read_buf.len(), buf.remaining());
            buf.put_slice(&self.read_buf[..len]);
            self.read_buf.drain(..len);
            return std::task::Poll::Ready(Ok(()));
        }

        match std::pin::Pin::new(&mut self.stream).poll_next(cx) {
            std::task::Poll::Ready(Some(Ok(WsMessage::Binary(data)))) => {
                let len = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..len]);
                if len < data.len() {
                    self.read_buf.extend_from_slice(&data[len..]);
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Some(Ok(WsMessage::Text(text)))) => {
                let data = text.as_bytes();
                let len = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..len]);
                if len < data.len() {
                    self.read_buf.extend_from_slice(&data[len..]);
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Some(Err(e))) => {
                std::task::Poll::Ready(Err(std::io::Error::other(e)))
            }
            std::task::Poll::Ready(Some(Ok(_))) => self.poll_read(cx, buf),
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "websocket closed",
            ))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl<S> AsyncWrite for WebSocketConn<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // 上一帧已提交但尚未 flush 完：只推进 flush，成功后按原长度报进度
        if let Some(pending_len) = self.write_pending {
            match std::pin::Pin::new(&mut self.stream).poll_flush(cx) {
                std::task::Poll::Ready(Ok(())) => {
                    self.write_pending = None;
                    return std::task::Poll::Ready(Ok(pending_len));
                }
                std::task::Poll::Ready(Err(e)) => {
                    self.write_pending = None;
                    return std::task::Poll::Ready(Err(std::io::Error::other(e)));
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }

        let msg = WsMessage::Binary(buf.to_vec());
        let len = buf.len();
        match std::pin::Pin::new(&mut self.stream).poll_ready(cx) {
            std::task::Poll::Ready(Ok(())) => {
                match std::pin::Pin::new(&mut self.stream).start_send(msg) {
                    Ok(_) => match std::pin::Pin::new(&mut self.stream).poll_flush(cx) {
                        std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(len)),
                        std::task::Poll::Ready(Err(e)) => {
                            std::task::Poll::Ready(Err(std::io::Error::other(e)))
                        }
                        std::task::Poll::Pending => {
                            // 帧已入队但未 flush 完：下次 poll_write 继续 flush
                            self.write_pending = Some(len);
                            std::task::Poll::Pending
                        }
                    },
                    Err(e) => std::task::Poll::Ready(Err(std::io::Error::other(e))),
                }
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(std::io::Error::other(e))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::new(&mut self.stream).poll_flush(cx) {
            std::task::Poll::Ready(Ok(())) => {
                self.write_pending = None;
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(std::io::Error::other(e))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::new(&mut self.stream).poll_close(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(std::io::Error::other(e))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl<S> FrpConn for WebSocketConn<S>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote_addr)
    }
}

/// 在既有流（TCP 或 TLS）之上完成 WebSocket 客户端握手
///
/// 与 [`ConnManager::connect_websocket`] 的区别：不负责建连与 TLS，仅在调用方
/// 已建立的流上做 HTTP Upgrade，便于「TLS 之后再叠加 WebSocket」（`wss`）。
pub async fn client_websocket_stream<S>(
    stream: S,
    url: &str,
    remote_addr: SocketAddr,
) -> Result<WebSocketConn<S>, NetError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (ws, _resp) = tokio_tungstenite::client_async(url, stream)
        .await
        .map_err(|e| NetError::Other(format!("websocket handshake failed: {e}")))?;
    Ok(WebSocketConn::new(ws, remote_addr))
}

/// 在既有流上完成 WebSocket 服务端握手（接受 Upgrade）
pub async fn accept_websocket_stream<S>(
    stream: S,
    remote_addr: SocketAddr,
) -> Result<WebSocketConn<S>, NetError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ws = tokio_tungstenite::accept_async(stream)
        .await
        .map_err(|e| NetError::Other(format!("websocket accept failed: {e}")))?;
    Ok(WebSocketConn::new(ws, remote_addr))
}

/// 从流中预读至多 `n` 字节（EOF / 超时前提前返回已读到的部分）
///
/// 用于「先看前几个字节再决定如何解析」的嗅探场景（如 TLS 之后判断是否
/// WebSocket 升级）。读到的字节需由调用方通过 [`PrefixedStream`] 回放。
pub async fn read_prefix<S>(
    stream: &mut S,
    n: usize,
    timeout: Duration,
) -> Result<Vec<u8>, NetError>
where
    S: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; n];
    let mut filled = 0usize;
    let fut = async {
        while filled < n {
            match stream.read(&mut buf[filled..]).await {
                Ok(0) => break,
                Ok(k) => filled += k,
                Err(e) => return Err(NetError::Io(e)),
            }
        }
        Ok::<(), NetError>(())
    };
    match tokio::time::timeout(timeout, fut).await {
        Ok(r) => {
            r?;
            buf.truncate(filled);
            Ok(buf)
        }
        // 超时不算致命：按已读到的字节返回（可能为空）
        Err(_) => {
            buf.truncate(filled);
            Ok(buf)
        }
    }
}

/// 前缀回放流：先吐出预先读出的字节，再委托给底层流
///
/// 用于「嗅探前 N 字节做协议判定，但后续仍需完整字节流」的场景。
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    /// 用预读字节与底层流构造
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }

    /// 取回底层流（丢弃未消费的前缀）
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S> AsyncRead for PrefixedStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let remaining = &self.prefix[self.pos..];
            let len = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..len]);
            self.pos += len;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for PrefixedStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S> FrpConn for PrefixedStream<S>
where
    S: FrpConn,
{
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.inner.remote_addr()
    }
}

/// TCP 监听器
pub struct TcpListener {
    inner: TokioTcpListener,
}

impl TcpListener {
    /// 绑定到指定地址
    ///
    /// # 参数
    ///
    /// * `addr` - 要绑定的地址
    pub async fn bind(addr: &SocketAddr) -> Result<Self, std::io::Error> {
        let inner = TokioTcpListener::bind(addr).await?;
        Ok(Self { inner })
    }

    /// 接受一个新连接
    pub async fn accept(&self) -> Result<(TokioTcpStream, SocketAddr), std::io::Error> {
        self.inner.accept().await
    }
}

/// UDP 监听器
pub struct UdpListener {
    inner: TokioUdpSocket,
}

impl UdpListener {
    /// 绑定到指定地址
    ///
    /// # 参数
    ///
    /// * `addr` - 要绑定的地址
    pub async fn bind(addr: &SocketAddr) -> Result<Self, std::io::Error> {
        let inner = TokioUdpSocket::bind(addr).await?;
        Ok(Self { inner })
    }

    /// 从远程地址接收数据
    ///
    /// # 参数
    ///
    /// * `buf` - 接收数据的缓冲区
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), std::io::Error> {
        self.inner.recv_from(buf).await
    }

    /// 发送数据到指定地址
    ///
    /// # 参数
    ///
    /// * `buf` - 要发送的数据
    /// * `addr` - 目标地址
    pub async fn send_to(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize, std::io::Error> {
        self.inner.send_to(buf, addr).await
    }
}

/// 跳过证书验证的结构体，用于客户端不验证服务器证书的场景
#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
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
            SignatureScheme::ED448,
        ]
    }
}

/// TLS 配置
pub struct TlsConfig {
    server_config: Option<Arc<tokio_rustls::rustls::ServerConfig>>,
    client_config: Option<Arc<tokio_rustls::rustls::ClientConfig>>,
}

impl Clone for TlsConfig {
    fn clone(&self) -> Self {
        Self {
            server_config: self.server_config.clone(),
            client_config: self.client_config.clone(),
        }
    }
}

impl TlsConfig {
    /// 从文件创建服务器 TLS 配置
    pub fn new_server(cert_file: &str, key_file: &str) -> Result<Self, NetError> {
        let cert_file = std::fs::File::open(cert_file)?;
        let mut cert_reader = BufReader::new(cert_file);
        let cert_chain: Result<Vec<CertificateDer<'static>>, _> =
            rustls_pemfile::certs(&mut cert_reader).collect();
        let cert_chain = cert_chain.map_err(|e| NetError::PemDecode(format!("{}", e)))?;

        let key_file_path = key_file.to_string();
        let key_file = std::fs::File::open(&key_file_path)?;
        let mut key_reader = BufReader::new(key_file);
        let pkcs8_keys: Result<Vec<_>, _> =
            rustls_pemfile::pkcs8_private_keys(&mut key_reader).collect();
        let mut keys: Vec<PrivateKeyDer<'static>> = pkcs8_keys
            .map_err(|e| NetError::PemDecode(format!("{}", e)))?
            .into_iter()
            .map(|k| k.into())
            .collect();

        if keys.is_empty() {
            let key_file = std::fs::File::open(&key_file_path)?;
            let mut key_reader = BufReader::new(key_file);
            let rsa_keys: Result<Vec<_>, _> =
                rustls_pemfile::rsa_private_keys(&mut key_reader).collect();
            let rsa_keys: Vec<PrivateKeyDer<'static>> = rsa_keys
                .map_err(|e| NetError::PemDecode(format!("{}", e)))?
                .into_iter()
                .map(|k| k.into())
                .collect();
            keys.extend(rsa_keys);
        }

        if keys.is_empty() {
            return Err(NetError::Other("No private key found in file".to_string()));
        }
        let key = keys.remove(0);

        let config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?;

        Ok(Self {
            server_config: Some(Arc::new(config)),
            client_config: None,
        })
    }

    /// 创建客户端 TLS 配置，信任自定义 CA 证书文件
    pub fn new_client_with_ca_file(ca_file: &str) -> Result<Self, NetError> {
        let cert_file = std::fs::File::open(ca_file)?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs: Result<Vec<CertificateDer<'static>>, _> =
            rustls_pemfile::certs(&mut cert_reader).collect();
        let certs = certs.map_err(|e| NetError::PemDecode(format!("{}", e)))?;

        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        for cert in certs {
            root_store.add(cert).map_err(NetError::Tls)?;
        }

        let config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(Arc::new(root_store))
            .with_no_client_auth();

        Ok(Self {
            server_config: None,
            client_config: Some(Arc::new(config)),
        })
    }

    /// 创建客户端 TLS 配置（跳过证书验证）
    /// 仅使用 TLS 加密，但不验证服务器证书
    /// 类似于原版 frp 中没有 trustedCaFile 时的行为
    pub fn new_client_insecure() -> Result<Self, NetError> {
        log::warn!(
            "TLS client configured with certificate verification DISABLED: \
             traffic is encrypted but the server identity is NOT authenticated"
        );
        let verifier = SkipServerVerification;
        let config = tokio_rustls::rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();

        Ok(Self {
            server_config: None,
            client_config: Some(Arc::new(config)),
        })
    }

    /// 创建客户端 TLS 配置（使用系统根证书）
    pub fn new_client() -> Result<Self, NetError> {
        let root_certs: Vec<CertificateDer<'static>> = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .map(|ta| CertificateDer::from(ta.subject_public_key_info.to_vec()))
            .collect();

        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        for cert in root_certs {
            root_store.add(cert).map_err(NetError::Tls)?;
        }

        let config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(Arc::new(root_store))
            .with_no_client_auth();

        Ok(Self {
            server_config: None,
            client_config: Some(Arc::new(config)),
        })
    }

    /// 创建使用**运行时生成**的自签名证书的服务器 TLS 配置
    ///
    /// 证书与私钥仅在内存中存在，进程每次启动都重新生成：
    /// - 私钥不再随源码分发，拿到仓库的人无法据此伪造服务端身份
    /// - 但仍是自签名证书，客户端默认不验证时仅提供加密不提供认证；
    ///   需要认证请配置 `transport.tls.cert_file` / `key_file`（服务端）
    ///   与 `transport.tls.trusted_ca_file`（客户端）
    pub fn new_server_with_runtime_cert() -> Result<Self, NetError> {
        log::warn!(
            "Using a RUNTIME-GENERATED self-signed TLS certificate (fresh per process): \
             encryption only, server identity NOT authenticated. \
             Configure transport.tls.cert_file/key_file with your own certificate in production."
        );

        let cert = rcgen::generate_simple_self_signed(vec![
            "frp-server.local".to_string(),
            "localhost".to_string(),
        ])
        .map_err(|e| {
            NetError::Other(format!("failed to generate self-signed certificate: {}", e))
        })?;

        let cert_der = cert.cert.der().to_owned();
        let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

        let config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der.into())?;

        Ok(Self {
            server_config: Some(Arc::new(config)),
            client_config: None,
        })
    }

    /// 接受 TLS 连接（服务端）
    ///
    /// # 参数
    ///
    /// * `stream` - 底层 TCP 流
    pub async fn accept(
        &self,
        stream: TokioTcpStream,
    ) -> Result<server::TlsStream<TokioTcpStream>, std::io::Error> {
        if let Some(config) = &self.server_config {
            let acceptor = TlsAcceptor::from(config.clone());
            acceptor.accept(stream).await.map_err(std::io::Error::other)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a server config",
            ))
        }
    }

    /// 建立 TLS 连接（客户端）
    ///
    /// # 参数
    ///
    /// * `domain` - 服务器域名
    /// * `stream` - 底层 TCP 流
    pub async fn connect(
        &self,
        domain: &str,
        stream: TokioTcpStream,
    ) -> Result<client::TlsStream<TokioTcpStream>, std::io::Error> {
        if let Some(config) = &self.client_config {
            let server_name = ServerName::try_from(domain.to_string()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid server name")
            })?;
            let connector = TlsConnector::from(config.clone());
            connector
                .connect(server_name, stream)
                .await
                .map_err(std::io::Error::other)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a client config",
            ))
        }
    }

    /// 接受 TLS 连接（泛型底层流）
    ///
    /// 与 [`TlsConfig::accept`] 相同，但底层流不限于 `TcpStream`，
    /// 供插件（任意访客连接）与多路复用（yamux 流上的 TLS）使用。
    pub async fn accept_stream<S>(&self, stream: S) -> Result<server::TlsStream<S>, std::io::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if let Some(config) = &self.server_config {
            let acceptor = TlsAcceptor::from(config.clone());
            acceptor.accept(stream).await.map_err(std::io::Error::other)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a server config",
            ))
        }
    }

    /// 建立 TLS 连接（泛型底层流）
    ///
    /// 与 [`TlsConfig::connect`] 相同，但底层流不限于 `TcpStream`，
    /// 供插件与多路复用（yamux 流上的 TLS）使用。
    pub async fn connect_stream<S>(
        &self,
        domain: &str,
        stream: S,
    ) -> Result<client::TlsStream<S>, std::io::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if let Some(config) = &self.client_config {
            let server_name = ServerName::try_from(domain.to_string()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid server name")
            })?;
            let connector = TlsConnector::from(config.clone());
            connector
                .connect(server_name, stream)
                .await
                .map_err(std::io::Error::other)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a client config",
            ))
        }
    }
}

/// 网络连接管理器
///
/// 统一管理所有网络连接，包括 TCP、TLS、WebSocket 和 KCP 连接。
pub struct ConnManager {
    /// TLS 配置
    pub tls_config: Option<TlsConfig>,
    pool_manager: PoolManager,
}

impl ConnManager {
    /// 创建新的连接管理器
    ///
    /// # 参数
    ///
    /// * `tls_config` - TLS 配置
    /// * `max_pool_size` - 连接池最大大小
    pub fn new(tls_config: Option<TlsConfig>, max_pool_size: usize) -> Self {
        let pool_config = PoolConfig {
            max_size: max_pool_size,
            ..Default::default()
        };

        Self {
            tls_config,
            pool_manager: PoolManager::new(pool_config),
        }
    }

    /// 建立 TCP 连接（使用连接池）
    ///
    /// # 参数
    ///
    /// * `addr` - 目标地址
    pub async fn connect_tcp(&self, addr: &SocketAddr) -> Result<PooledConn, std::io::Error> {
        let pool = self.pool_manager.get_or_create_pool(*addr).await;
        pool.get().await
    }

    /// 建立 TLS 连接（使用连接池）
    ///
    /// # 参数
    ///
    /// * `domain` - 服务器域名
    /// * `addr` - 目标地址
    pub async fn connect_tls(
        &self,
        domain: &str,
        addr: &SocketAddr,
    ) -> Result<client::TlsStream<TokioTcpStream>, std::io::Error> {
        let pooled = self.connect_tcp(addr).await?;
        if let Some(tls_config) = &self.tls_config {
            tls_config.connect(domain, pooled.conn).await
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TLS config not set",
            ))
        }
    }

    /// 建立 KCP 连接
    ///
    /// # 参数
    ///
    /// * `addr` - 目标地址
    pub async fn connect_kcp(&self, addr: &SocketAddr) -> Result<KcpConn, NetError> {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(NetError::Io)?;
        socket.connect(addr).await.map_err(NetError::Io)?;
        let socket = std::sync::Arc::new(socket);
        KcpConn::new(socket, *addr, None).await
    }

    /// 将连接放回连接池
    ///
    /// # 参数
    ///
    /// * `addr` - 连接目标地址
    /// * `conn` - 要放回的连接
    pub async fn put_back(&self, addr: SocketAddr, conn: PooledConn) {
        if let Some(pool) = self.pool_manager.get_pool(addr).await {
            pool.put(conn).await;
        }
    }

    /// 获取 TLS 配置
    pub fn get_tls_config(&self) -> Option<&TlsConfig> {
        self.tls_config.as_ref()
    }

    /// 获取连接池管理器
    pub fn get_pool_manager(&self) -> &PoolManager {
        &self.pool_manager
    }
}

// 导出连接池模块
pub mod pool;

/// 应用层加密（use_encryption）：AES-256-GCM 工作连接加密流
pub mod compress;
pub mod crypto;

/// wire protocol v2：魔数 + 帧化握手 + 能力协商 + 方向性 AEAD 控制通道
pub mod wire_v2;
pub use wire_v2::{
    check_magic, client_handshake, server_handshake, write_magic, BootstrapInfo, ClientHello,
    CryptoContext, Frame, ServerHello, WireError, FRAME_TYPE_CLIENT_HELLO, FRAME_TYPE_MESSAGE,
    FRAME_TYPE_SERVER_HELLO, MAGIC_V2,
};

/// PROXY protocol 头构造（v1 文本 / v2 二进制，frpc 写给本地服务）
pub mod proxy_protocol;

/// 极简 HTTP/1.1 客户端（OIDC 拉取 issuer/JWKS/token、插件回调共用）
pub mod http;

// 重新导出连接池类型

/// KCP 协议的输出适配器，将 KCP 输出通过 channel 传递给异步 UDP 写任务
struct KcpChannelOutput {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl std::io::Write for KcpChannelOutput {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let data = buf.to_vec();
        let _ = self.tx.try_send(data);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// KCP 连接，实现了 AsyncRead + AsyncWrite + FrpConn
///
/// 内部通过后台任务维护 KCP 会话，将 UDP 数据包与 KCP 协议进行转换。
pub struct KcpConn {
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    remote_addr: SocketAddr,
    read_buf: Vec<u8>,
    _handle: tokio::task::JoinHandle<()>,
}

impl KcpConn {
    /// 创建新的 KCP 连接（客户端）
    ///
    /// # 参数
    ///
    /// * `socket` - UDP socket
    /// * `remote_addr` - 远程地址
    /// * `conv` - KCP 会话 ID（可选，默认为随机值）
    pub async fn new(
        socket: std::sync::Arc<tokio::net::UdpSocket>,
        remote_addr: SocketAddr,
        conv: Option<u32>,
    ) -> Result<Self, NetError> {
        let conv = conv.unwrap_or_else(rand::random::<u32>);
        Self::create_impl(socket, remote_addr, conv, None).await
    }

    /// 接受 KCP 连接（服务端）
    ///
    /// # 参数
    ///
    /// * `socket` - UDP socket
    /// * `first_packet` - 收到的第一个数据包（用于提取 conv）
    /// * `remote_addr` - 远程地址
    pub async fn accept(
        socket: std::sync::Arc<tokio::net::UdpSocket>,
        first_packet: &[u8],
        remote_addr: SocketAddr,
    ) -> Result<Self, NetError> {
        let conv = if first_packet.len() >= 4 {
            u32::from_le_bytes([
                first_packet[0],
                first_packet[1],
                first_packet[2],
                first_packet[3],
            ])
        } else {
            rand::random::<u32>()
        };
        Self::create_impl(socket, remote_addr, conv, Some(first_packet.to_vec())).await
    }

    async fn create_impl(
        socket: std::sync::Arc<tokio::net::UdpSocket>,
        remote_addr: SocketAddr,
        conv: u32,
        initial_input: Option<Vec<u8>>,
    ) -> Result<Self, NetError> {
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
        let (user_tx, mut user_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
        let (user_rx_tx, user_rx_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

        let socket_clone = socket.clone();

        let handle = tokio::spawn(async move {
            let kcp_output = KcpChannelOutput { tx: out_tx };
            let mut kcp = kcp::Kcp::new(conv, kcp_output);

            kcp.set_nodelay(true, 10, 2, true);
            kcp.set_wndsize(128, 128);
            let _ = kcp.set_mtu(1400);

            if let Some(data) = initial_input {
                let _ = kcp.input(&data);
            }

            let mut buf = vec![0u8; 65535];
            let mut recv_buf = vec![0u8; 65535];
            let mut tick_interval = tokio::time::interval(std::time::Duration::from_millis(10));

            loop {
                tokio::select! {
                    _ = tick_interval.tick() => {
                        // 使用毫秒时间戳
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u32;
                        let _ = kcp.update(now_ms);
                        // 更新后 flush 以发送 ACK 和重传数据
                        let _ = kcp.flush();
                    }

                    recv_result = socket_clone.recv_from(&mut buf) => {
                        match recv_result {
                            Ok((n, src)) if src == remote_addr => {
                                let _ = kcp.input(&buf[..n]);
                                while let Ok(n) = kcp.recv(&mut recv_buf) {
                                    if user_rx_tx.send(recv_buf[..n].to_vec()).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            Ok((_n, _src)) => {}
                            Err(_e) => {
                                break;
                            }
                        }
                    }

                    Some(out_data) = out_rx.recv() => {
                        let _ = socket_clone.send_to(&out_data, &remote_addr).await;
                    }

                    Some(user_data) = user_rx.recv() => {
                        let _ = kcp.send(&user_data);
                        let _ = kcp.flush();
                        while let Ok(n) = kcp.recv(&mut recv_buf) {
                            if user_rx_tx.send(recv_buf[..n].to_vec()).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            rx: user_rx_rx,
            tx: user_tx,
            remote_addr,
            read_buf: Vec::new(),
            _handle: handle,
        })
    }
}

impl AsyncRead for KcpConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.read_buf.is_empty() {
            let len = std::cmp::min(self.read_buf.len(), buf.remaining());
            buf.put_slice(&self.read_buf[..len]);
            self.read_buf.drain(..len);
            return std::task::Poll::Ready(Ok(()));
        }

        match self.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(data)) => {
                let len = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..len]);
                if len < data.len() {
                    self.read_buf.extend_from_slice(&data[len..]);
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "KCP connection closed",
            ))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl AsyncWrite for KcpConn {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let data = buf.to_vec();
        let len = data.len();
        match self.tx.try_send(data) {
            Ok(_) => std::task::Poll::Ready(Ok(len)),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // Channel is full, would block
                std::task::Poll::Pending
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => std::task::Poll::Ready(Err(
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "KCP send channel closed"),
            )),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl FrpConn for KcpConn {
    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote_addr)
    }
}

/// KCP 监听器，用于服务端接受 KCP 连接
pub struct KcpListener {
    socket: std::sync::Arc<tokio::net::UdpSocket>,
}

impl KcpListener {
    pub async fn bind(addr: SocketAddr) -> Result<Self, std::io::Error> {
        let socket = tokio::net::UdpSocket::bind(addr).await?;
        Ok(Self {
            socket: std::sync::Arc::new(socket),
        })
    }

    pub async fn accept(&self) -> Result<(KcpConn, SocketAddr), NetError> {
        let mut buf = vec![0u8; 65535];
        let (n, src_addr) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(NetError::Io)?;

        let first_packet = buf[..n].to_vec();
        let conn = KcpConn::accept(self.socket.clone(), &first_packet, src_addr).await?;

        Ok((conn, src_addr))
    }
}
pub use pool::{ConnPool, PoolConfig, PoolManager, PoolStats, PooledConn};

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 前缀回放：先吐前缀字节，再委托底层流
    #[tokio::test]
    async fn prefixed_stream_replays_prefix_then_inner() {
        let (mut a, b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            a.write_all(b"world").await.expect("write inner");
        });
        let mut stream = PrefixedStream::new(b"hello ".to_vec(), b);
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.expect("read all");
        assert_eq!(out, b"hello world");
    }

    /// 前缀回放：前缀跨多次 poll_read 仍完整（buf 小于前缀）
    #[tokio::test]
    async fn prefixed_stream_replays_across_short_reads() {
        let (mut a, b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            a.write_all(b"XY").await.expect("write inner");
            drop(a);
        });
        let mut stream = PrefixedStream::new(b"ABCDE".to_vec(), b);
        let mut small = [0u8; 2];
        let mut got = Vec::new();
        loop {
            let n = stream.read(&mut small).await.expect("read");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&small[..n]);
        }
        assert_eq!(got, b"ABCDEXY");
    }

    /// 预读前缀：正常读满 n 字节
    #[tokio::test]
    async fn read_prefix_reads_requested_bytes() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(b"GET /~!frp").await.expect("write");
        let prefix = read_prefix(&mut b, 4, Duration::from_secs(1))
            .await
            .expect("read prefix");
        assert_eq!(prefix, b"GET ");
    }

    /// 预读前缀：对端不发数据时按超时返回已读到的部分（不报错）
    #[tokio::test]
    async fn read_prefix_times_out_gracefully() {
        let (_a, mut b) = tokio::io::duplex(64);
        let prefix = read_prefix(&mut b, 4, Duration::from_millis(50))
            .await
            .expect("should not error");
        assert!(prefix.is_empty());
    }

    /// 前缀嗅探：部分字节（"G"）也应被判为 WebSocket 前缀
    #[test]
    fn websocket_prefix_sniffing() {
        let is_ws = |b: &[u8]| !b.is_empty() && (b.starts_with(b"GET ") || b"GET ".starts_with(b));
        assert!(is_ws(b"GET "));
        assert!(is_ws(b"GET /~!frp HTTP/1.1"));
        assert!(is_ws(b"G"));
        assert!(is_ws(b"GET"));
        assert!(!is_ws(b""));
        assert!(!is_ws(b"POST"));
        assert!(!is_ws(&[TCP_MUX_MAGIC]));
        assert!(!is_ws(&[0x16, 0x03, 0x01, 0x00]));
    }

    /// WebSocket 适配层：`write_all`（不显式 flush）后对端必须能收到完整字节流。
    ///
    /// 这是回归守卫：Sink 在 `start_send` 后需 `poll_flush` 才真正发包，
    /// 而 frp 上层只调用 `write_all`，因此适配层必须自行驱动 flush。
    #[tokio::test]
    async fn websocket_conn_write_all_flushes_without_explicit_flush() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.expect("accept");
            let mut ws = accept_websocket_stream(stream, peer)
                .await
                .expect("server handshake");
            let mut buf = vec![0u8; 13];
            ws.read_exact(&mut buf).await.expect("read payload");
            ws
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut ws = client_websocket_stream(
            tcp,
            &format!("ws://127.0.0.1:{}{FRP_WS_PATH}", addr.port()),
            addr,
        )
        .await
        .expect("client handshake");

        // 只 write_all，不 flush：内容应完整到达对端
        ws.write_all(b"hello frp ws!").await.expect("write_all");

        let _server_ws = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server task within timeout")
            .expect("server task join");
    }
}
